//! Historical reference decoding only. Strict private DTOs do not deserialize
//! authority grants and never turn retained signatures or observations current.
use super::super::{self as retention, SignedCandidateContext};
use serde::Deserialize;
use std::collections::BTreeMap;
use wholepact_storage_security::bundle::{
    BundleError, JournalKind,
    recovery::{RecoveryCell, RecoveryProvenance, RecoveryTable, VerifiedRecoveryComponent},
};

pub struct SignedRecoveryReference {
    pub result_id: String,
    pub request_digest: String,
    pub scope_digest: String,
    pub context: SignedCandidateContext,
    pub signature_set_digest: String,
    pub maximum_actions: usize,
    pub retained_result_digest: Option<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Context {
    principal_id: String,
    candidate_id: String,
    proof_job_id: String,
    checkpoint_scope_digest: String,
    proved_artifact_digest: String,
    manifest_digest: String,
    review_binding: String,
    delivery_provenance_digest: String,
    account_ids: Vec<String>,
    local_operator: String,
    purpose: String,
    retention_policy: String,
}
impl Context {
    fn checked(self) -> Result<SignedCandidateContext, BundleError> {
        let context = SignedCandidateContext {
            principal_id: self.principal_id,
            candidate_id: self.candidate_id,
            proof_job_id: self.proof_job_id,
            checkpoint_scope_digest: self.checkpoint_scope_digest,
            proved_artifact_digest: self.proved_artifact_digest,
            manifest_digest: self.manifest_digest,
            review_binding: self.review_binding,
            delivery_provenance_digest: self.delivery_provenance_digest,
            account_ids: self.account_ids,
            local_operator: self.local_operator,
            purpose: self.purpose,
            retention_policy: self.retention_policy,
        };
        retention::validate(&context).map_err(|_| BundleError::Integrity)?;
        Ok(context)
    }
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Scope {
    context: Context,
    signature_set_digest: String,
}

pub fn recovery_references(
    source: &VerifiedRecoveryComponent,
) -> Result<Vec<SignedRecoveryReference>, BundleError> {
    recovery_references_parts(source.provenance(), source.tables())
}
/// Trusted complete-inventory validator after native private-data approval.
/// It creates no user disclosure, signature, live journal or replay capability.
pub fn successor_recovery_references(
    source: &wholepact_storage_security::bundle::recovery::evidence::RecoveredEvidence,
) -> Result<Vec<SignedRecoveryReference>, BundleError> {
    recovery_references_parts(source.provenance(), source.tables())
}

/// Complete owner validation of a sealed archived current journal. This is
/// historical inspection only and cannot start a worker or release an artifact.
pub fn archived_recovery_references(
    source: &wholepact_storage_security::generation_archive::ArchivedOrdinarySource,
) -> Result<Vec<SignedRecoveryReference>, BundleError> {
    recovery_references_parts(source.provenance(), source.tables())
}

pub(super) fn recovery_references_parts(
    provenance: &RecoveryProvenance,
    tables: &[RecoveryTable],
) -> Result<Vec<SignedRecoveryReference>, BundleError> {
    checked_kind(provenance, JournalKind::SignedResults, &super::TEMPLATE)?;
    let intents = table(
        tables,
        "signed_intents",
        &[
            "result_id",
            "principal_id",
            "idem_key",
            "request_digest",
            "scope",
            "signatures",
        ],
    )?;
    let results = table(tables, "signed_results", &["result_id", "bytes", "digest"])?;
    if intents.rows().len() > 64 {
        return Err(BundleError::Limit);
    }
    let mut output = BTreeMap::new();
    for row in intents.rows() {
        let c = row.cells();
        if c.len() != 6 {
            return Err(BundleError::Integrity);
        }
        let id = text(&c[0])?;
        let principal = text(&c[1])?;
        let idem = text(&c[2])?;
        let request = text(&c[3])?;
        let bytes = blob(&c[4], 16384)?;
        let signatures = blob(&c[5], 10240)?;
        let scope: Scope = serde_json::from_slice(bytes).map_err(|_| BundleError::Integrity)?;
        let context = scope.context.checked()?;
        let maximum_actions = (1..=crate::proving::MAX_PROVING_ACTIONS)
            .find(|maximum| {
                retention::framed(&[bytes, signatures, &(*maximum as u64).to_le_bytes()]) == request
            })
            .ok_or(BundleError::Integrity)?;
        if context.principal_id != principal
            || !(16..=128).contains(&idem.len())
            || !idem.bytes().all(|byte| (33..=126).contains(&byte))
            || scope.signature_set_digest != retention::hash(signatures)
            || format!(
                "signed-{}",
                retention::framed(&[principal.as_bytes(), idem.as_bytes()])
            ) != id
        {
            return Err(BundleError::Integrity);
        }
        if output
            .insert(
                id.to_string(),
                SignedRecoveryReference {
                    result_id: id.into(),
                    request_digest: request.into(),
                    scope_digest: retention::hash(bytes),
                    context,
                    signature_set_digest: scope.signature_set_digest,
                    maximum_actions,
                    retained_result_digest: None,
                },
            )
            .is_some()
        {
            return Err(BundleError::Integrity);
        }
    }
    for row in results.rows() {
        let c = row.cells();
        if c.len() != 3 {
            return Err(BundleError::Integrity);
        }
        let item = output.get_mut(text(&c[0])?).ok_or(BundleError::Integrity)?;
        let digest = text(&c[2])?;
        if item.retained_result_digest.is_some()
            || retention::hash(blob(&c[1], retention::MAX_BYTES)?) != digest
        {
            return Err(BundleError::Integrity);
        }
        item.retained_result_digest = Some(digest.into());
    }
    Ok(output.into_values().collect())
}

#[cfg(feature = "transaction-checkpoint")]
pub struct TransactionRecoveryReference {
    pub checkpoint_id: String,
    pub signed_result_id: String,
    pub request_digest: String,
    pub context: SignedCandidateContext,
    pub signature_set_digest: String,
    pub signed_request_digest: String,
    pub signed_candidate_digest: String,
    pub retained_transaction_digest: Option<String>,
    pub retained_transaction_id: Option<String>,
}
#[cfg(feature = "transaction-checkpoint")]
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct TransactionScope {
    signed_scope: Scope,
    signed_result_id: String,
    signed_request_digest: String,
    signed_candidate_digest: String,
}

#[cfg(feature = "transaction-checkpoint")]
pub fn transaction_recovery_references(
    source: &VerifiedRecoveryComponent,
) -> Result<Vec<TransactionRecoveryReference>, BundleError> {
    transaction_recovery_references_parts(source.provenance(), source.tables())
}
#[cfg(feature = "transaction-checkpoint")]
pub fn successor_transaction_recovery_references(
    source: &wholepact_storage_security::bundle::recovery::evidence::RecoveredEvidence,
) -> Result<Vec<TransactionRecoveryReference>, BundleError> {
    transaction_recovery_references_parts(source.provenance(), source.tables())
}
#[cfg(feature = "transaction-checkpoint")]
pub fn archived_transaction_recovery_references(
    source: &wholepact_storage_security::generation_archive::ArchivedOrdinarySource,
) -> Result<Vec<TransactionRecoveryReference>, BundleError> {
    transaction_recovery_references_parts(source.provenance(), source.tables())
}
#[cfg(feature = "transaction-checkpoint")]
pub(super) fn transaction_recovery_references_parts(
    provenance: &RecoveryProvenance,
    tables: &[RecoveryTable],
) -> Result<Vec<TransactionRecoveryReference>, BundleError> {
    checked_kind(
        provenance,
        JournalKind::ExactTransactions,
        &retention::transaction::backup::TEMPLATE,
    )?;
    let intents = table(
        tables,
        "transaction_intents",
        &[
            "checkpoint_id",
            "signed_result_id",
            "request_digest",
            "scope",
        ],
    )?;
    let results = table(
        tables,
        "transaction_results",
        &["checkpoint_id", "bytes", "digest", "txid"],
    )?;
    if intents.rows().len() > 64 {
        return Err(BundleError::Limit);
    }
    let mut output = BTreeMap::new();
    for row in intents.rows() {
        let c = row.cells();
        if c.len() != 4 {
            return Err(BundleError::Integrity);
        }
        let id = text(&c[0])?;
        let bytes = blob(&c[3], 16384)?;
        let scope: TransactionScope =
            serde_json::from_slice(bytes).map_err(|_| BundleError::Integrity)?;
        let context = scope.signed_scope.context.checked()?;
        if scope.signed_result_id != text(&c[1])?
            || !scope.signed_result_id.starts_with("signed-")
            || !digest(&scope.signed_result_id[7..])
            || !digest(&scope.signed_scope.signature_set_digest)
            || !digest(&scope.signed_request_digest)
            || !digest(&scope.signed_candidate_digest)
            || retention::framed(&[b"transaction-checkpoint-v1", bytes]) != text(&c[2])?
            || format!(
                "transaction-{}",
                retention::framed(&[b"transaction-id-v1", scope.signed_result_id.as_bytes()])
            ) != id
        {
            return Err(BundleError::Integrity);
        }
        if output
            .insert(
                id.to_string(),
                TransactionRecoveryReference {
                    checkpoint_id: id.into(),
                    signed_result_id: scope.signed_result_id,
                    request_digest: text(&c[2])?.into(),
                    context,
                    signature_set_digest: scope.signed_scope.signature_set_digest,
                    signed_request_digest: scope.signed_request_digest,
                    signed_candidate_digest: scope.signed_candidate_digest,
                    retained_transaction_digest: None,
                    retained_transaction_id: None,
                },
            )
            .is_some()
        {
            return Err(BundleError::Integrity);
        }
    }
    for row in results.rows() {
        let c = row.cells();
        if c.len() != 4 {
            return Err(BundleError::Integrity);
        }
        let item = output.get_mut(text(&c[0])?).ok_or(BundleError::Integrity)?;
        let bytes = blob(&c[1], retention::MAX_BYTES)?;
        let saved_digest = text(&c[2])?;
        let txid = text(&c[3])?;
        let mut cursor = std::io::Cursor::new(bytes);
        let parsed = zcash_primitives::transaction::Transaction::read(
            &mut cursor,
            zcash_protocol::consensus::BranchId::Nu7,
        )
        .map_err(|_| BundleError::Integrity)?;
        if item.retained_transaction_digest.is_some()
            || retention::hash(bytes) != saved_digest
            || cursor.position() != bytes.len() as u64
            || parsed.txid().to_string() != txid
        {
            return Err(BundleError::Integrity);
        }
        item.retained_transaction_digest = Some(saved_digest.into());
        item.retained_transaction_id = Some(txid.into());
    }
    Ok(output.into_values().collect())
}

fn checked_kind(
    p: &RecoveryProvenance,
    kind: JournalKind,
    template: &wholepact_storage_security::bundle::JournalTemplate,
) -> Result<(), BundleError> {
    if p.kind == kind
        && p.application_id == template.application_id
        && p.schema_version == template.schema_version
    {
        Ok(())
    } else {
        Err(BundleError::Unsupported)
    }
}
fn table<'a>(
    tables: &'a [RecoveryTable],
    name: &str,
    columns: &[&str],
) -> Result<&'a RecoveryTable, BundleError> {
    let table = tables
        .iter()
        .find(|table| table.name() == name)
        .ok_or(BundleError::Unsupported)?;
    if table
        .columns()
        .iter()
        .map(String::as_str)
        .ne(columns.iter().copied())
    {
        return Err(BundleError::Integrity);
    }
    Ok(table)
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
#[cfg(feature = "transaction-checkpoint")]
fn digest(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}
