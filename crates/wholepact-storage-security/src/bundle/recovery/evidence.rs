//! Immutable recovered artifact copies. Every original cell, hidden rowid,
//! trigger and AUTOINCREMENT sequence is retained, but no original runtime
//! identity, queue worker, replay action, observation or consent is activated.

pub mod history;

use super::super::{
    BundleError, ComponentManifest, JournalKind, JournalTemplate, MAX_CELL, quote,
    validate_component_template, verify_restored_rows,
};
use super::generation::{GenerationBinding, Purpose};
use super::{
    RecoveryCell, RecoveryProvenance, RecoveryRow, RecoveryTable, VerifiedRecoveryComponent,
    generation, wallet,
};
use crate::DatabaseKey;
use rusqlite::{Connection, TransactionBehavior, types::ValueRef};
use std::path::Path;

type Result<T> = std::result::Result<T, BundleError>;

/// Non-cloneable, non-deserializable immutable evidence. No live connection,
/// mutable journal conversion, query callback, or replay permission is exposed.
/// The caller must separately authorize any private artifact disclosure.
pub struct RecoveredEvidence {
    historical_binding: history::HistoricalSourceBinding,
    archive_origin: Option<history::HistoricalArchiveOrigin>,
    provenance: RecoveryProvenance,
    generation: GenerationBinding,
    tables: Vec<RecoveryTable>,
}
impl RecoveredEvidence {
    pub fn disclosure_identity(&self) -> history::HistoricalDisclosureIdentity<'_> {
        history::HistoricalDisclosureIdentity::from_evidence(self)
    }
    pub fn archive_origin(&self) -> Option<&history::HistoricalArchiveOrigin> {
        self.archive_origin.as_ref()
    }
    /// Only authenticated archive factories can create the sealed origin.
    /// Keep the original generation and component provenance unchanged.
    pub(crate) fn attach_archive_origin(&mut self, origin: history::HistoricalArchiveOrigin) {
        self.archive_origin = Some(origin);
    }
    pub fn historical_binding(&self) -> history::HistoricalSourceBinding {
        self.historical_binding.clone()
    }
    pub fn provenance(&self) -> &RecoveryProvenance {
        &self.provenance
    }
    pub fn generation(&self) -> &GenerationBinding {
        &self.generation
    }
    pub fn tables(&self) -> &[RecoveryTable] {
        &self.tables
    }
}

// The reusable kernel is private. Each public entry point is fixed to one
// journal kind; its owning crate supplies the current executable-owned schema.
macro_rules! evidence_boundary {
    ($copy:ident, $open:ident, $archived:ident, $kind:ident) => {
        pub fn $copy(
            source: &VerifiedRecoveryComponent,
            template: &'static JournalTemplate,
            path: impl AsRef<Path>,
            key: &DatabaseKey,
            binding: &GenerationBinding,
        ) -> Result<()> {
            reconstruct(
                source,
                template,
                path.as_ref(),
                key,
                binding,
                JournalKind::$kind,
            )
        }
        pub fn $open(
            path: impl AsRef<Path>,
            key: &DatabaseKey,
            binding: &GenerationBinding,
            expected: &RecoveryProvenance,
            template: &'static JournalTemplate,
        ) -> Result<RecoveredEvidence> {
            open(
                path.as_ref(),
                None,
                key,
                binding,
                expected,
                template,
                JournalKind::$kind,
            )
        }
        /// Authenticate relocated immutable evidence against its original path.
        /// The host must first authenticate the complete archive's exact mapping.
        /// No original path is accessed and no runtime capability is returned.
        pub fn $archived(
            path: impl AsRef<Path>,
            original_path: &Path,
            key: &DatabaseKey,
            binding: &GenerationBinding,
            expected: &RecoveryProvenance,
            template: &'static JournalTemplate,
        ) -> Result<RecoveredEvidence> {
            open(
                path.as_ref(),
                Some(original_path),
                key,
                binding,
                expected,
                template,
                JournalKind::$kind,
            )
        }
    };
}
evidence_boundary!(
    reconstruct_coordination_evidence,
    open_coordination_evidence,
    open_archived_coordination_evidence,
    CoordinationAuthority
);
evidence_boundary!(
    reconstruct_inbox_evidence,
    open_inbox_evidence,
    open_archived_inbox_evidence,
    TransportInbox
);
evidence_boundary!(
    reconstruct_outbox_evidence,
    open_outbox_evidence,
    open_archived_outbox_evidence,
    TransportOutbox
);
evidence_boundary!(
    reconstruct_submission_evidence,
    open_submission_evidence,
    open_archived_submission_evidence,
    Submission
);
evidence_boundary!(
    reconstruct_proof_evidence,
    open_proof_evidence,
    open_archived_proof_evidence,
    ProofWitness
);
evidence_boundary!(
    reconstruct_signed_results_evidence,
    open_signed_results_evidence,
    open_archived_signed_results_evidence,
    SignedResults
);
evidence_boundary!(
    reconstruct_transactions_evidence,
    open_transactions_evidence,
    open_archived_transactions_evidence,
    ExactTransactions
);
evidence_boundary!(
    reconstruct_wallet_scan_evidence,
    open_wallet_scan_evidence,
    open_archived_wallet_scan_evidence,
    WalletScan
);

fn reconstruct(
    source: &VerifiedRecoveryComponent,
    template: &'static JournalTemplate,
    path: &Path,
    key: &DatabaseKey,
    binding: &GenerationBinding,
    kind: JournalKind,
) -> Result<()> {
    if source.provenance().kind != kind || template.kind != kind {
        return Err(BundleError::Unsupported);
    }
    let component = generation::source_component(source, template)?;
    let base_schema = generation::compiled_schema(template, false)?;
    let schema = generation::compiled_schema(template, true)?;
    let marker = generation::marker(
        binding,
        source.provenance(),
        template,
        path,
        Purpose::ImmutableEvidence,
        Some(component.clone()),
    )?;
    if let Some(mut output) = generation::prepare_output(path, key, &marker, template, &schema)? {
        let transaction = output.transaction_with_behavior(TransactionBehavior::Immediate)?;
        generation::require_staging(&transaction)?;
        wallet::populate(&transaction, source, template, &base_schema)?;
        generation::install_marker(&transaction, &marker, template)?;
        generation::verify_marker(&transaction, &marker, template, &schema)?;
        verify_restored_rows(&transaction, component)?;
        transaction.commit()?;
        crate::checkpoint_and_sync(&output, path)?;
        drop(output);
    }
    // Also checks every row on completed retries; marker/schema equality alone
    // must not launder modified, missing or extra historical artifacts.
    let persisted = crate::open_encrypted_read_only(path, key)?;
    persisted.execute_batch("BEGIN DEFERRED;")?;
    generation::verify_marker(&persisted, &marker, template, &schema)?;
    verify_restored_rows(&persisted, component)
}

fn open(
    path: &Path,
    original_path: Option<&Path>,
    key: &DatabaseKey,
    binding: &GenerationBinding,
    expected: &RecoveryProvenance,
    template: &'static JournalTemplate,
    kind: JournalKind,
) -> Result<RecoveredEvidence> {
    if expected.kind != kind || template.kind != kind {
        return Err(BundleError::Unsupported);
    }
    let schema = generation::compiled_schema(template, true)?;
    let read = crate::open_encrypted_read_only(path, key)?;
    read.execute_batch("BEGIN DEFERRED;")?;
    // Check app/schema before selecting any marker content. Arbitrary imported
    // SQLite schema or views never become executable decoder instructions.
    if wallet::application_id(&read)? != generation::RECOVERED_GENERATION_APPLICATION_ID
        || wallet::exact_schema(&read)? != schema
    {
        return Err(BundleError::Integrity);
    }
    let stored = generation::read_marker(&read)?;
    let component = stored.component.as_ref().ok_or(BundleError::Integrity)?;
    if component.id != expected.component_id
        || component.kind != expected.kind
        || component.application_id != expected.application_id
        || component.schema_version != expected.schema_version
        || component.rows != expected.rows
        || component.digest != expected.component_digest
    {
        return Err(BundleError::Integrity);
    }
    validate_component_template(component, template)?;
    let marker = match original_path {
        Some(original_path) => generation::archived_marker(
            binding,
            expected,
            template,
            original_path,
            Purpose::ImmutableEvidence,
            Some(component.clone()),
        )?,
        None => generation::marker(
            binding,
            expected,
            template,
            path,
            Purpose::ImmutableEvidence,
            Some(component.clone()),
        )?,
    };
    generation::verify_marker(&read, &marker, template, &schema)?;
    verify_restored_rows(&read, component)?;
    let tables = read_tables(&read, component)?;
    Ok(RecoveredEvidence {
        historical_binding: history::HistoricalSourceBinding::fresh(),
        archive_origin: None,
        provenance: expected.clone(),
        generation: binding.clone(),
        tables,
    })
}

fn read_tables(
    connection: &Connection,
    component: &ComponentManifest,
) -> Result<Vec<RecoveryTable>> {
    let mut tables = Vec::with_capacity(component.tables.len());
    for table in &component.tables {
        let columns = table
            .columns
            .iter()
            .map(|column| quote(column))
            .collect::<Result<Vec<_>>>()?
            .join(",");
        let mut statement = connection.prepare(&format!(
            "SELECT {}{} FROM {}",
            if table.rowid { "rowid," } else { "" },
            columns,
            quote(&table.name)?
        ))?;
        let mut query = statement.query([])?;
        let mut rows = Vec::with_capacity(table.rows);
        while let Some(row) = query.next()? {
            if rows.len() >= table.rows {
                return Err(BundleError::Integrity);
            }
            let mut cells = Vec::with_capacity(table.columns.len());
            for index in 0..table.columns.len() {
                cells.push(match row.get_ref(index + usize::from(table.rowid))? {
                    ValueRef::Null => RecoveryCell::Null,
                    ValueRef::Integer(value) => RecoveryCell::Integer(value),
                    ValueRef::Real(value) => RecoveryCell::RealBits(value.to_bits()),
                    ValueRef::Text(value) => {
                        if value.len() > MAX_CELL {
                            return Err(BundleError::Limit);
                        }
                        RecoveryCell::Text(
                            std::str::from_utf8(value)
                                .map_err(|_| BundleError::Integrity)?
                                .into(),
                        )
                    }
                    ValueRef::Blob(value) => {
                        if value.len() > MAX_CELL {
                            return Err(BundleError::Limit);
                        }
                        RecoveryCell::Blob(value.to_vec())
                    }
                });
            }
            rows.push(RecoveryRow {
                rowid: if table.rowid { Some(row.get(0)?) } else { None },
                cells,
            });
        }
        if rows.len() != table.rows {
            return Err(BundleError::Integrity);
        }
        tables.push(RecoveryTable {
            name: table.name.clone(),
            columns: table.columns.clone(),
            rows,
            has_rowid: table.rowid,
        });
    }
    Ok(tables)
}
