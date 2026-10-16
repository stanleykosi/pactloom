//! Typed historical result projections. No signed PCZT or signature byte getter,
//! live checkpoint conversion, submission, replay, or proof extraction exists.
use super::recovery_references::*;
use serde::Serialize;
use wholepact_storage_security::bundle::{
    BundleError,
    recovery::{
        RecoveryTable,
        evidence::{RecoveredEvidence, history::*},
    },
};

type Result<T> = std::result::Result<T, BundleError>;
#[derive(Serialize)]
pub struct HistoricalSignedResultMetadata {
    pub origin: HistoricalOrigin,
    pub references: HistoricalReferences,
    pub request_digest: String,
    pub scope_digest: String,
    pub signature_set_digest: String,
    pub retained_result_digest: Option<String>,
    pub restrictions: HistoricalRestrictions,
}
fn context_references(context: &super::super::SignedCandidateContext) -> HistoricalReferences {
    HistoricalReferences {
        historical_principal_id: context.principal_id.clone(),
        candidate_id: Some(context.candidate_id.clone()),
        proof_job_id: Some(context.proof_job_id.clone()),
        account_ids: context.account_ids.clone(),
        manifest_digest: Some(context.manifest_digest.clone()),
        proof_scope_digest: Some(context.checkpoint_scope_digest.clone()),
        proved_artifact_digest: Some(context.proved_artifact_digest.clone()),
        ..HistoricalReferences::default()
    }
}
pub fn historical_signed_result<'a>(
    source: &RecoveredEvidence,
    principal: &str,
    result_id: &str,
    authority: &'a dyn HistoricalDisclosureAuthority,
) -> Result<HistoricalDisclosure<'a, HistoricalSignedResultMetadata>> {
    historical_signed_result_parts(
        source.disclosure_identity(),
        source.tables(),
        principal,
        result_id,
        authority,
    )
}

/// Disclose only typed historical metadata from an authenticated archived source.
pub fn archived_historical_signed_result<'a>(
    source: &wholepact_storage_security::generation_archive::ArchivedOrdinarySource,
    principal: &str,
    result_id: &str,
    authority: &'a dyn HistoricalDisclosureAuthority,
) -> Result<HistoricalDisclosure<'a, HistoricalSignedResultMetadata>> {
    historical_signed_result_parts(
        source.disclosure_identity(),
        source.tables(),
        principal,
        result_id,
        authority,
    )
}

fn historical_signed_result_parts<'a>(
    identity: HistoricalDisclosureIdentity<'_>,
    tables: &[RecoveryTable],
    principal: &str,
    result_id: &str,
    authority: &'a dyn HistoricalDisclosureAuthority,
) -> Result<HistoricalDisclosure<'a, HistoricalSignedResultMetadata>> {
    let item = recovery_references_parts(identity.provenance(), tables)?
        .into_iter()
        .find(|item| item.result_id == result_id)
        .ok_or(BundleError::Invalid)?;
    let mut references = context_references(&item.context);
    references.artifact_id = item.result_id.clone();
    references.signed_result_id = Some(item.result_id);
    references.signed_request_digest = Some(item.request_digest.clone());
    references.signed_candidate_digest = item.retained_result_digest.clone();
    let metadata = HistoricalSignedResultMetadata {
        origin: HistoricalOrigin::from_source(identity),
        references: references.clone(),
        request_digest: item.request_digest,
        scope_digest: item.scope_digest,
        signature_set_digest: item.signature_set_digest,
        retained_result_digest: item.retained_result_digest,
        restrictions: HistoricalRestrictions::default(),
    };
    HistoricalDisclosure::authorize_from_source(
        identity,
        principal,
        HistoricalAction::SignedResultMetadata,
        references,
        metadata,
        authority,
    )
}

#[cfg(feature = "transaction-checkpoint")]
#[derive(Serialize)]
pub struct HistoricalTransactionMetadata {
    pub origin: HistoricalOrigin,
    pub references: HistoricalReferences,
    pub request_digest: String,
    pub signature_set_digest: String,
    pub retained_transaction_bytes: Option<usize>,
    pub restrictions: HistoricalRestrictions,
}
#[cfg(feature = "transaction-checkpoint")]
fn selected_transaction<'s>(
    identity: HistoricalDisclosureIdentity<'_>,
    tables: &'s [RecoveryTable],
    checkpoint_id: &str,
) -> Result<(HistoricalTransactionMetadata, Option<&'s [u8]>)> {
    use wholepact_storage_security::bundle::recovery::RecoveryCell;
    let item = transaction_recovery_references_parts(identity.provenance(), tables)?
        .into_iter()
        .find(|item| item.checkpoint_id == checkpoint_id)
        .ok_or(BundleError::Invalid)?;
    let bytes = tables
        .iter()
        .find(|table| table.name() == "transaction_results")
        .ok_or(BundleError::Integrity)?
        .rows()
        .iter()
        .find_map(|row| match row.cells() {
            [RecoveryCell::Text(id), RecoveryCell::Blob(bytes), _, _] if id == checkpoint_id => {
                Some(bytes.as_slice())
            }
            _ => None,
        });
    if bytes.is_some() != item.retained_transaction_digest.is_some() {
        return Err(BundleError::Integrity);
    }
    let mut references = context_references(&item.context);
    references.artifact_id = item.checkpoint_id.clone();
    references.transaction_checkpoint_id = Some(item.checkpoint_id);
    references.signed_result_id = Some(item.signed_result_id);
    references.signed_request_digest = Some(item.signed_request_digest);
    references.signed_candidate_digest = Some(item.signed_candidate_digest);
    references.transaction_id = item.retained_transaction_id;
    references.transaction_bytes_digest = item.retained_transaction_digest;
    Ok((
        HistoricalTransactionMetadata {
            origin: HistoricalOrigin::from_source(identity),
            references,
            request_digest: item.request_digest,
            signature_set_digest: item.signature_set_digest,
            retained_transaction_bytes: bytes.map(<[u8]>::len),
            restrictions: HistoricalRestrictions::default(),
        },
        bytes,
    ))
}
#[cfg(feature = "transaction-checkpoint")]
pub fn historical_transaction<'a>(
    source: &RecoveredEvidence,
    principal: &str,
    checkpoint_id: &str,
    authority: &'a dyn HistoricalDisclosureAuthority,
) -> Result<HistoricalDisclosure<'a, HistoricalTransactionMetadata>> {
    historical_transaction_parts(
        source.disclosure_identity(),
        source.tables(),
        principal,
        checkpoint_id,
        authority,
    )
}

#[cfg(feature = "transaction-checkpoint")]
pub fn archived_historical_transaction<'a>(
    source: &wholepact_storage_security::generation_archive::ArchivedOrdinarySource,
    principal: &str,
    checkpoint_id: &str,
    authority: &'a dyn HistoricalDisclosureAuthority,
) -> Result<HistoricalDisclosure<'a, HistoricalTransactionMetadata>> {
    historical_transaction_parts(
        source.disclosure_identity(),
        source.tables(),
        principal,
        checkpoint_id,
        authority,
    )
}

#[cfg(feature = "transaction-checkpoint")]
fn historical_transaction_parts<'a>(
    identity: HistoricalDisclosureIdentity<'_>,
    tables: &[RecoveryTable],
    principal: &str,
    checkpoint_id: &str,
    authority: &'a dyn HistoricalDisclosureAuthority,
) -> Result<HistoricalDisclosure<'a, HistoricalTransactionMetadata>> {
    let (metadata, _) = selected_transaction(identity, tables, checkpoint_id)?;
    HistoricalDisclosure::authorize_from_source(
        identity,
        principal,
        HistoricalAction::TransactionMetadata,
        metadata.references.clone(),
        metadata,
        authority,
    )
}

/// The only recovered-byte disclosure: one exact already-retained transaction,
/// under current native approval to a new local private file. A usable transaction
/// and signatures may remain usable after export; copies cannot be revoked.
#[cfg(feature = "transaction-checkpoint")]
pub struct HistoricalTransactionExport<'a> {
    bytes: zeroize::Zeroizing<Vec<u8>>,
    scope: HistoricalDisclosureScope,
    lease: Box<dyn HistoricalDisclosureLease + 'a>,
}
#[cfg(feature = "transaction-checkpoint")]
pub fn historical_transaction_export<'a>(
    source: &RecoveredEvidence,
    principal: &str,
    checkpoint_id: &str,
    destination: &std::path::Path,
    authority: &'a dyn HistoricalDisclosureAuthority,
) -> Result<HistoricalTransactionExport<'a>> {
    historical_transaction_export_parts(
        source.disclosure_identity(),
        source.tables(),
        principal,
        checkpoint_id,
        destination,
        authority,
    )
}

/// The same exact-byte, new-private-file, current one-shot lease gate applies to
/// archived transactions. No raw transaction getter or alternate export exists.
#[cfg(feature = "transaction-checkpoint")]
pub fn archived_historical_transaction_export<'a>(
    source: &wholepact_storage_security::generation_archive::ArchivedOrdinarySource,
    principal: &str,
    checkpoint_id: &str,
    destination: &std::path::Path,
    authority: &'a dyn HistoricalDisclosureAuthority,
) -> Result<HistoricalTransactionExport<'a>> {
    historical_transaction_export_parts(
        source.disclosure_identity(),
        source.tables(),
        principal,
        checkpoint_id,
        destination,
        authority,
    )
}

#[cfg(feature = "transaction-checkpoint")]
fn historical_transaction_export_parts<'a>(
    identity: HistoricalDisclosureIdentity<'_>,
    tables: &[RecoveryTable],
    principal: &str,
    checkpoint_id: &str,
    destination: &std::path::Path,
    authority: &'a dyn HistoricalDisclosureAuthority,
) -> Result<HistoricalTransactionExport<'a>> {
    let (metadata, bytes) = selected_transaction(identity, tables, checkpoint_id)?;
    let bytes = bytes.ok_or(BundleError::Integrity)?;
    let scope = HistoricalDisclosureScope::from_source(
        identity,
        principal,
        HistoricalAction::ExportExactTransaction,
        metadata.references,
        HistoricalDestination::NewPrivateLocalFile(destination.into()),
        bytes,
    )?;
    let lease = acquire_checked(authority, &scope)?;
    check_lease(&*lease, &scope)?;
    Ok(HistoricalTransactionExport {
        bytes: zeroize::Zeroizing::new(bytes.to_vec()),
        scope,
        lease,
    })
}
#[cfg(feature = "transaction-checkpoint")]
impl HistoricalTransactionExport<'_> {
    pub fn export(self) -> Result<()> {
        export_exact_transaction_bytes(&self.scope, &*self.lease, &self.bytes)
    }
}
