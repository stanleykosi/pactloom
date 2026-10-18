//! Trusted-native historical summaries from a quarantined coordination bundle.
//! This deliberately cannot reopen the restore as a mutable Store or read private
//! participant records. Every read needs separate exact historical-read consent.
use wholepact_storage_security::bundle::BundleError;
pub use wholepact_storage_security::bundle::history::{
    HistoricalAgreement, HistoricalAgreementEvent, HistoricalChange, HistoricalEventPage,
    HistoricalObservation, HistoryAction, HistoryAuthority, HistoryBinding, HistoryLease,
    HistoryOpenRequest, HistoryScope, QuarantinedCoordinationHistory,
};

/// Authenticate the archive and exact restored component against its original
/// executable-owned Store schema. Key/path arguments belong to the trusted local host;
/// this is never an ordinary HTTP or scoped-agreement-reader export API.
pub fn open_quarantined_history(
    request: HistoryOpenRequest<'_>,
) -> Result<QuarantinedCoordinationHistory, BundleError> {
    let manifest =
        wholepact_storage_security::bundle::inspect(request.archive, request.archive_key)?;
    let component = manifest
        .components
        .iter()
        .find(|component| component.id == request.component_id)
        .ok_or(BundleError::Invalid)?;
    if component.kind != wholepact_storage_security::bundle::JournalKind::CoordinationAuthority
        || component.application_id != 0
    {
        return Err(BundleError::Unsupported);
    }
    let template = crate::bundle::coordination_template_for_schema(component.schema_version)?;
    let source = wholepact_storage_security::bundle::recovery::VerifiedRecoveryComponent::open(
        HistoryOpenRequest {
            archive: request.archive,
            archive_key: request.archive_key,
            component_id: request.component_id,
            restored_component: request.restored_component,
            restored_key: request.restored_key,
        },
        template,
    )?;
    if source.manifest() != &manifest {
        return Err(BundleError::Integrity);
    }
    validate_construction_history(source.provenance(), source.tables())?;
    QuarantinedCoordinationHistory::open(request, template)
}

/// Restriction-only validation of all manual construction history before any
/// protected projection. No historical rows become a live Store or admission.
pub fn validate_successor_construction_history(
    source: &wholepact_storage_security::bundle::recovery::evidence::RecoveredEvidence,
) -> Result<(), BundleError> {
    validate_construction_history(source.provenance(), source.tables())
}
fn validate_construction_history(
    provenance: &wholepact_storage_security::bundle::recovery::RecoveryProvenance,
    tables: &[wholepact_storage_security::bundle::recovery::RecoveryTable],
) -> Result<(), BundleError> {
    use wholepact_storage_security::bundle::{JournalKind, recovery::RecoveryCell};
    if provenance.kind != JournalKind::CoordinationAuthority || provenance.application_id != 0 {
        return Err(BundleError::Unsupported);
    }
    // Run over all four raw JSON columns before making the records-only
    // construction view. Event payloads remain opaque rather than being
    // mistaken for agreement envelopes or ignored because they are historical.
    crate::recovery::validate_no_private_input_projection_tables(tables)
        .map_err(|_| BundleError::Integrity)?;
    let template = crate::bundle::coordination_template_for_schema(provenance.schema_version)?;
    let records = tables
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
    // Inert validation view of authenticated records only. It has no marker,
    // key, file identity, quarantine conversion or Store constructor.
    let scratch = rusqlite::Connection::open_in_memory()?;
    scratch.execute_batch(template.create_sql)?;
    for row in records.rows() {
        let cells = row.cells();
        if cells.len() != 6 {
            return Err(BundleError::Integrity);
        }
        let Some(RecoveryCell::Text(kind)) = cells.first() else {
            return Err(BundleError::Integrity);
        };
        if !kind.starts_with("generation_manual_") {
            continue;
        }
        let values = cells
            .iter()
            .map(|cell| match cell {
                RecoveryCell::Text(value) => Ok(rusqlite::types::Value::Text(value.clone())),
                RecoveryCell::Integer(value) => Ok(rusqlite::types::Value::Integer(*value)),
                _ => Err(BundleError::Integrity),
            })
            .collect::<Result<Vec<_>, _>>()?;
        scratch.execute(
            "INSERT INTO records VALUES(?1,?2,?3,?4,?5,?6)",
            rusqlite::params_from_iter(values),
        )?;
    }
    let support = crate::recovery::construction_encoding_support(
        provenance.application_id,
        provenance.schema_version,
    )
    .map_err(|_| BundleError::Integrity)?;
    crate::backup::validate_construction_encoding(&scratch, support.0, support.1, support.2)
        .map_err(|_| BundleError::Integrity)
}
