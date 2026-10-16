//! Exact protected projection of an immutable original participant record. This
//! never returns a SettlementRecord, live Store, original grant or raw envelope.
use super::*;
use wholepact_storage_security::bundle::{
    BundleError, JournalKind,
    recovery::{
        RecoveryCell,
        evidence::{RecoveredEvidence, history::*},
    },
};
type HistoricalResult<T> = std::result::Result<T, BundleError>;

/// Caller selects original historical identity explicitly. Possession of these
/// labels is not ownership or permission; current native approval is separate.
#[derive(Clone, Serialize)]
pub struct HistoricalParticipantSelection {
    pub agreement_id: String,
    pub record_id: String,
    pub historical_owner_principal_id: String,
    pub historical_profile_id: String,
    pub participant_id: String,
    pub account_id: String,
}
#[derive(Serialize)]
pub struct HistoricalParticipantRecord {
    pub origin: HistoricalOrigin,
    pub references: HistoricalReferences,
    pub agreement_revision: u64,
    pub record_revision: u64,
    pub candidate_proposal_digest: String,
    pub retained_source_id: String,
    /// Typed approved terms only: no envelope, previews, permission, witness,
    /// automation state or archived arbitrary payload escapes this projection.
    pub approved_proposal: wholepact_core::ProposalInput,
    pub recorded_own_authorization: wholepact_core::records::OwnAuthorizationRecord,
    pub transaction: wholepact_core::records::ExactTransactionReference,
    pub historical_observation_count: usize,
    pub historical_settlement_invalidated: bool,
    pub restrictions: HistoricalRestrictions,
}

pub fn historical_participant_record<'a>(
    source: &RecoveredEvidence,
    principal: &str,
    selection: &HistoricalParticipantSelection,
    authority: &'a dyn HistoricalDisclosureAuthority,
) -> HistoricalResult<HistoricalDisclosure<'a, HistoricalParticipantRecord>> {
    let p = source.provenance();
    let template = wholepact_store::bundle::coordination_template_for_schema(p.schema_version)?;
    if p.kind != JournalKind::CoordinationAuthority
        || p.application_id != template.application_id
        || p.schema_version != template.schema_version
    {
        return Err(BundleError::Unsupported);
    }
    wholepact_store::history::validate_successor_construction_history(source)?;
    validate_selection(selection)?;
    let records = source
        .tables()
        .iter()
        .find(|table| table.name() == "records")
        .ok_or(BundleError::Integrity)?;
    if records.columns().iter().map(String::as_str).ne([
        "aggregate_type",
        "id",
        "revision",
        "payload",
        "created_at_ms",
        "updated_at_ms",
    ]) {
        return Err(BundleError::Integrity);
    }
    let mut selected = None;
    for row in records.rows() {
        let cells = row.cells();
        if cells.len() != 6 {
            return Err(BundleError::Integrity);
        }
        if text(&cells[0])? == "agreement" && text(&cells[1])? == selection.agreement_id {
            if selected.is_some() {
                return Err(BundleError::Integrity);
            }
            let payload: Value =
                serde_json::from_str(text(&cells[3])?).map_err(|_| BundleError::Integrity)?;
            let record = StoredRecord {
                id: selection.agreement_id.clone(),
                revision: u64::try_from(integer(&cells[2])?).map_err(|_| BundleError::Integrity)?,
                payload,
                created_at_ms: integer(&cells[4])?,
                updated_at_ms: integer(&cells[5])?,
            };
            selected = Some(project_record(
                &record,
                selection,
                source.disclosure_identity(),
            )?);
        }
    }
    let projection = selected.ok_or(BundleError::Invalid)?;
    HistoricalDisclosure::authorize(
        source,
        principal,
        HistoricalAction::ParticipantRecord,
        projection.references.clone(),
        projection,
        authority,
    )
}
/// Inspect the complete Store-owned archived generation before selecting a
/// record. This never turns the archive into a live Store or treats any retained
/// approval, observation, signature or permission as current authority.
pub fn archived_historical_participant_record<'a>(
    source: &wholepact_storage_security::generation_archive::ArchivedGenerationSource,
    principal: &str,
    selection: &HistoricalParticipantSelection,
    authority: &'a dyn HistoricalDisclosureAuthority,
) -> HistoricalResult<HistoricalDisclosure<'a, HistoricalParticipantRecord>> {
    validate_selection(selection)?;
    let inventory = crate::recovery::inspect_archived_coordination_recovery(source)
        .map_err(|_| BundleError::Integrity)?;
    let mut records = inventory
        .store_inventory()
        .agreements()
        .iter()
        .filter(|record| record.id == selection.agreement_id);
    let record = records.next().ok_or(BundleError::Invalid)?;
    if records.next().is_some() {
        return Err(BundleError::Integrity);
    }
    let identity = source.disclosure_identity();
    let projection = project_record(record, selection, identity)?;
    HistoricalDisclosure::authorize_from_source(
        identity,
        principal,
        HistoricalAction::ParticipantRecord,
        projection.references.clone(),
        projection,
        authority,
    )
}

fn validate_selection(selection: &HistoricalParticipantSelection) -> HistoricalResult<()> {
    for id in [
        &selection.agreement_id,
        &selection.record_id,
        &selection.historical_owner_principal_id,
        &selection.historical_profile_id,
        &selection.participant_id,
        &selection.account_id,
    ] {
        validate_identifier(id).map_err(|_| BundleError::Invalid)?;
    }
    Ok(())
}

// Both public entrypoints derive the sealed identity directly from their source.
// This private projection reuses the exact same canonical envelope and record
// checks; it does not expose a usable SettlementRecord or arbitrary saved JSON.
fn project_record(
    record: &StoredRecord,
    selection: &HistoricalParticipantSelection,
    identity: HistoricalDisclosureIdentity<'_>,
) -> HistoricalResult<HistoricalParticipantRecord> {
    let raw: Envelope =
        serde_json::from_value(record.payload.clone()).map_err(|_| BundleError::Integrity)?;
    if serde_json::to_value(&raw).map_err(|_| BundleError::Integrity)? != record.payload
        || record.id != selection.agreement_id
        || raw.view.agreement.agreement_id != selection.agreement_id
    {
        return Err(BundleError::Integrity);
    }
    let envelope = decode(record).map_err(|_| BundleError::Integrity)?;
    let retained = envelope
        .participant_records
        .get(&selection.record_id)
        .ok_or(BundleError::Invalid)?;
    let archive = &retained.record;
    if retained.owner_principal_id != selection.historical_owner_principal_id
        || retained.profile_id != selection.historical_profile_id
        || archive.own_authorization.participant_id != selection.participant_id
        || archive.own_authorization.account_id != selection.account_id
    {
        return Err(BundleError::Permission);
    }
    // Restore validates all internal links without giving the caller a
    // usable record object or letting archived observations become current.
    SettlementRecord::restore(archive.clone()).map_err(|_| BundleError::Integrity)?;
    let mut accounts = archive
        .proposal
        .manifest
        .participants
        .iter()
        .map(|item| item.account_id.clone())
        .collect::<Vec<_>>();
    accounts.sort();
    accounts.dedup();
    let references = HistoricalReferences {
        artifact_id: selection.record_id.clone(),
        historical_principal_id: retained.owner_principal_id.clone(),
        historical_profile_id: Some(retained.profile_id.clone()),
        agreement_id: Some(selection.agreement_id.clone()),
        candidate_id: Some(retained.candidate_id.clone()),
        record_id: Some(selection.record_id.clone()),
        participant_id: Some(selection.participant_id.clone()),
        account_ids: accounts,
        manifest_digest: Some(archive.own_authorization.manifest_digest.clone()),
        transaction_id: Some(archive.transaction.transaction_id.clone()),
        transaction_bytes_digest: Some(archive.transaction.transaction_bytes_digest.clone()),
        ..HistoricalReferences::default()
    };
    Ok(HistoricalParticipantRecord {
        origin: HistoricalOrigin::from_source(identity),
        references,
        agreement_revision: record.revision,
        record_revision: retained.record_revision,
        candidate_proposal_digest: retained.candidate_proposal_digest.clone(),
        retained_source_id: retained.retained_source_id.clone(),
        approved_proposal: archive.proposal.clone(),
        recorded_own_authorization: archive.own_authorization.clone(),
        transaction: archive.transaction.clone(),
        historical_observation_count: archive.observations.len(),
        historical_settlement_invalidated: retained.settlement_invalidated,
        restrictions: HistoricalRestrictions::default(),
    })
}

fn text(cell: &RecoveryCell) -> HistoricalResult<&str> {
    if let RecoveryCell::Text(value) = cell {
        Ok(value)
    } else {
        Err(BundleError::Integrity)
    }
}
fn integer(cell: &RecoveryCell) -> HistoricalResult<i64> {
    if let RecoveryCell::Integer(value) = cell {
        Ok(*value)
    } else {
        Err(BundleError::Integrity)
    }
}
