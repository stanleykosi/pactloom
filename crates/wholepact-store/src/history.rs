//! Trusted-native historical summaries from a quarantined coordination bundle.
//! This deliberately cannot reopen the restore as a mutable Store or read private
//! participant records. Every read needs separate exact historical-read consent.
use wholepact_storage_security::bundle::BundleError;
use wholepact_storage_security::bundle::history as storage_history;
pub use wholepact_storage_security::bundle::history::{
    HistoricalAgreement, HistoricalAgreementEvent, HistoricalChange, HistoricalEventPage,
    HistoricalObservation, HistoryAction, HistoryAuthority, HistoryBinding, HistoryLease,
    HistoryOpenRequest, HistoryScope,
};

/// Store-checked history, bound to the complete content scanned at open.
/// The lower history owner and its unchecked opener are deliberately not exposed.
/// This wrapper neither grants historical-read consent nor creates a live Store.
/// Content equality establishes neither freshness nor rollback protection.
pub struct QuarantinedCoordinationHistory {
    inner: storage_history::QuarantinedCoordinationHistory,
    binding: HistoryBinding,
    scanned_profile_id: String,
    scanned_component_id: String,
    scanned_bundle_digest: String,
}

impl QuarantinedCoordinationHistory {
    /// Opaque enrollment identity only. A binding is not a content check or consent;
    /// every data output separately joins the pinned inner scope to the scanned content.
    pub fn binding(&self) -> HistoryBinding {
        self.binding.clone()
    }

    pub fn agreement(
        &self,
        principal: &str,
        id: &str,
        authority: &dyn HistoryAuthority,
    ) -> Result<Option<HistoricalAgreement>, BundleError> {
        let checked = CheckedHistoryAuthority {
            history: self,
            authority,
        };
        self.inner.agreement(principal, id, &checked)
    }

    pub fn events(
        &self,
        principal: &str,
        id: &str,
        after_sequence: u64,
        limit: usize,
        authority: &dyn HistoryAuthority,
    ) -> Result<HistoricalEventPage, BundleError> {
        let checked = CheckedHistoryAuthority {
            history: self,
            authority,
        };
        self.inner
            .events(principal, id, after_sequence, limit, &checked)
    }
}

// Deny-only adapter. The lower owner presents its actual pinned identity before
// any agreement/event SELECT. Only matching content reaches the caller's real
// authority, with its exact scope and real borrowed lease unchanged. The lower
// owner holds/checks that lease before reading and again before returning data.
struct CheckedHistoryAuthority<'history, 'authority> {
    history: &'history QuarantinedCoordinationHistory,
    authority: &'authority dyn HistoryAuthority,
}

impl HistoryAuthority for CheckedHistoryAuthority<'_, '_> {
    fn acquire<'a>(
        &'a self,
        scope: &HistoryScope<'_>,
    ) -> Result<Box<dyn HistoryLease + 'a>, BundleError> {
        if scope.source != &self.history.binding
            || scope.profile_id != self.history.scanned_profile_id
            || scope.component_id != self.history.scanned_component_id
            || scope.bundle_digest != self.history.scanned_bundle_digest
        {
            return Err(BundleError::Integrity);
        }
        self.authority.acquire(scope)
    }
}

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
    let scanned_profile_id = source.provenance().profile_id.clone();
    let scanned_component_id = source.provenance().component_id.clone();
    let scanned_bundle_digest = source.provenance().bundle_digest.clone();

    // Deterministic test-only substitution at the actual second-open boundary.
    // No production callback, caller-selected identity or raw constructor exists.
    #[cfg(all(test, target_os = "linux"))]
    let replacement = private_workspace_history_tests::take_second_open();
    #[cfg(all(test, target_os = "linux"))]
    let request = match &replacement {
        Some((archive, restored_component)) => HistoryOpenRequest {
            archive,
            restored_component,
            ..request
        },
        None => request,
    };

    let inner = storage_history::QuarantinedCoordinationHistory::open(request, template)?;
    let binding = inner.binding();
    // The lower opener authenticates all restored rows against its manifest and
    // retains a pinned private snapshot. Every later output compares that exact
    // manifest identity to the content scanned above. This closes a content swap
    // between opens; it does not replace either opener's source-copy/quiescence
    // requirements or claim that the second open performed no authentication reads.
    Ok(QuarantinedCoordinationHistory {
        inner,
        binding,
        scanned_profile_id,
        scanned_component_id,
        scanned_bundle_digest,
    })
}

#[cfg(all(test, target_os = "linux"))]
mod private_workspace_history_tests;

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
