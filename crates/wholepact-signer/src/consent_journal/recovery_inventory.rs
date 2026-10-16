//! Complete sealed-source recovery consumer. No issuer or historical-to-live
//! conversion exists here. All reconstruction uses private, in-memory SQLite;
//! no quarantined source connection is opened or changed by this module.
use super::*;
use rusqlite::Transaction;
use wholepact_authority::ReconciledAuthorityHistory;

/// Review-only observation of original receipt crash state. Ciphertext and raw
/// returned signatures stay in the sealed source, bound by the complete journal
/// commitment. These pins never renew a clock, inbox identity or native decision.
#[derive(Serialize)]
struct RecoveryReceiptEvidence {
    authorization_id: String,
    terms_digest: String,
    package_digest: String,
    envelope_digest: String,
    authenticated_receipt_digest: Option<String>,
    accepted_receipt_digest: Option<String>,
}
#[derive(Serialize)]
struct SourceTableInventory {
    name: String,
    rows: usize,
}

/// Non-deserializable complete history plan. The serialized representation is
/// native review data only, with a distinct v2 digest domain at the call site.
#[derive(Serialize)]
pub(super) struct PreparedRecoveryHistory {
    reservations: writer_history::PreparedWriterHistory,
    source_tables: Vec<SourceTableInventory>,
    retained_receipts: Vec<RecoveryReceiptEvidence>,
    source_has_offline: bool,
    pending_birth_commit: Option<wholepact_authority::pending_birth::PendingBirthCommitRecord>,
}
impl PreparedRecoveryHistory {
    pub(super) fn read(
        source: &VerifiedSignerRecoverySource,
        history: &ReconciledAuthorityHistory,
    ) -> Result<Self> {
        with_complete_source(source, |tx| {
            let account = storage::read_account(tx)?;
            let local = writer_history::WriterLocalInventory::read(
                tx,
                &account,
                (MAX_BACKUP_ROWS, MAX_BACKUP_ENCODED_BYTES),
            )?;
            // Unlike ordinary handoff, recovery may not retain an unmatched
            // online original. The writer kernel separately rejects unmatched
            // minimal/full offline admissions and all cross-origin collisions.
            local.require_all_online_originals_replayed(history)?;
            // Same-ID receipt observations must agree with complete retained/
            // replayed offline terms and package, and cannot alias online origins.
            offline_receipts::validate_reconciled(tx, &account.account_id, history)?;
            // Preflight also checks surviving genesis/exclusion provenance;
            // source shape alone cannot erase a post-backup permanent exclusion.
            // Preparation retains the same result separately for native display
            // and deterministic successor storage.
            account_use_recovery::reconcile_complete(source, history)?;
            let reservations = writer_history::PreparedWriterHistory::prepare(&local, history)?;
            Ok(Self {
                pending_birth_commit: history.pending_birth_commit().cloned(),
                reservations,
                source_tables: source
                    .tables()
                    .iter()
                    .map(|table| SourceTableInventory {
                        name: table.name().to_owned(),
                        rows: table.rows().len(),
                    })
                    .collect(),
                retained_receipts: receipt_inventory(tx, &account.account_id)?,
                source_has_offline: source.tables().iter().any(|table| {
                    table.name().starts_with("signer_offline_") && !table.rows().is_empty()
                }),
            })
        })
    }
    pub(super) fn uses_v2_review(&self) -> bool {
        self.has_offline() || self.pending_birth_commit.is_some()
    }
    pub(super) fn has_offline(&self) -> bool {
        self.source_has_offline || self.reservations.has_offline()
    }
    /// Explicit availability gate, independent of absent factories. It covers
    /// prereview/receipt-only sources as well as local-only and witness-only
    /// reservations. Removing it requires coordinated downstream qualification.
    pub(super) fn require_enabled(&self) -> Result<()> {
        self.reservations.require_enabled()?;
        if self.has_offline() {
            return Err(JournalError::OfflineHistoryUnsupported);
        }
        Ok(())
    }
    pub(super) fn legacy_online_permits(&self) -> Result<&[ReservationPermit]> {
        self.require_enabled()?;
        self.reservations.legacy_online_permits()
    }
    pub(super) fn require_identical(&self, current: &Self) -> Result<()> {
        if digest("wholepact:complete-recovery-history:v2", self)?
            != digest("wholepact:complete-recovery-history:v2", current)?
        {
            return Err(JournalError::Conflict);
        }
        Ok(())
    }
    /// Called only from the fresh native-approved successor transaction. The
    /// gate runs again before mutation, and the complete imported source must
    /// still equal the prepared local snapshot, including account-use/receipts.
    pub(super) fn import_on(&self, tx: &Transaction<'_>, account: &str) -> Result<()> {
        self.require_enabled()?;
        let state = storage::read_account(tx)?;
        if state.account_id != account {
            return Err(JournalError::InvalidBinding);
        }
        let local = writer_history::WriterLocalInventory::read(
            tx,
            &state,
            (MAX_BACKUP_ROWS, MAX_BACKUP_ENCODED_BYTES),
        )?;
        self.reservations.require_unchanged_local(&local)?;
        self.reservations.import_complete(tx, account)
    }
}

/// Materialize all exact source tables into the current additive schema. The
/// original version template is checked first and never relabeled. New tables
/// are empty; original rowids, payloads, epochs and quarantine flags are copied
/// verbatim. A rollback-only in-memory transaction cannot activate a profile.
pub(super) fn with_complete_source<T>(
    source: &VerifiedSignerRecoverySource,
    f: impl FnOnce(&Transaction<'_>) -> Result<T>,
) -> Result<T> {
    validate_component_coverage(source)?;
    verify_source_layout(source)?;
    let mut c = Connection::open_in_memory()?;
    c.execute_batch("PRAGMA foreign_keys=ON; PRAGMA temp_store=MEMORY;")?;
    let tx = c.transaction_with_behavior(TransactionBehavior::Deferred)?;
    tx.execute_batch(SCHEMA)?;
    tx.execute_batch("PRAGMA defer_foreign_keys=ON;")?;
    import_all(&tx, source)?;
    // Includes every offline prereview/admission/result row, all three account-
    // use tables and all three receipt tables on every feature configuration.
    storage::verify_schema(&tx)?;
    let violations: i64 =
        tx.query_row("SELECT count(*) FROM pragma_foreign_key_check", [], |r| {
            r.get(0)
        })?;
    if violations != 0 {
        return Err(JournalError::InvalidBinding);
    }
    let result = f(&tx)?;
    tx.rollback()?;
    Ok(result)
}

fn verify_source_layout(source: &VerifiedSignerRecoverySource) -> Result<()> {
    if source.provenance().application_id != APPLICATION_ID
        || source.provenance().kind != JournalKind::SignerConsentAuthority
    {
        return Err(JournalError::InvalidBinding);
    }
    let template = recovery_template(source.provenance().schema_version)?;
    let reference = Connection::open_in_memory()?;
    reference.execute_batch(template.create_sql)?;
    let mut q =
        reference.prepare("SELECT name FROM sqlite_schema WHERE type='table' ORDER BY name")?;
    let names = q
        .query_map([], |r| r.get::<_, String>(0))?
        .collect::<std::result::Result<Vec<_>, _>>()?;
    if names.len() != source.tables().len() {
        return Err(JournalError::InvalidBinding);
    }
    for name in names {
        let table = source
            .tables()
            .iter()
            .find(|table| table.name() == name)
            .ok_or(JournalError::InvalidBinding)?;
        let quoted = name.replace('"', "\"\"");
        let q = reference.prepare(&format!("SELECT * FROM \"{quoted}\" WHERE 0"))?;
        if table
            .columns()
            .iter()
            .map(String::as_str)
            .collect::<Vec<_>>()
            != q.column_names()
            || !table.has_rowid()
            || table
                .rows()
                .iter()
                .any(|row| row.rowid().is_none() || row.cells().len() != table.columns().len())
        {
            return Err(JournalError::InvalidBinding);
        }
    }
    Ok(())
}
fn receipt_inventory(c: &Connection, account: &str) -> Result<Vec<RecoveryReceiptEvidence>> {
    offline_receipts::validate_all(c, account)?;
    let mut q = c.prepare(
        "SELECT i.authorization_id,i.terms_digest,i.package_digest,i.envelope_digest,a.receipt_digest,x.receipt_digest FROM signer_offline_review_inputs i LEFT JOIN signer_offline_review_authenticated a USING(authorization_id) LEFT JOIN signer_offline_review_accepted x USING(authorization_id) ORDER BY i.authorization_id",
    )?;
    let rows = q
        .query_map([], |r| {
            Ok(RecoveryReceiptEvidence {
                authorization_id: r.get(0)?,
                terms_digest: r.get(1)?,
                package_digest: r.get(2)?,
                envelope_digest: r.get(3)?,
                authenticated_receipt_digest: r.get(4)?,
                accepted_receipt_digest: r.get(5)?,
            })
        })?
        .collect::<std::result::Result<Vec<_>, _>>()?;
    Ok(rows)
}

#[cfg(test)]
#[path = "recovery_inventory_tests.rs"]
mod tests;
