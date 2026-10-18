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
    // Version18 is the immutable pre-financial template. Version19 is the
    // distinct exact financial-only template; unknown/discovery layouts cannot
    // be reclassified merely because their table names overlap.
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

#[cfg(test)]
mod frozen18_inventory_tests {
    use super::*;
    use std::{os::unix::fs::PermissionsExt, sync::Mutex};
    use wholepact_storage_security::bundle::*;

    struct HistoricalAdapter(Mutex<Connection>);
    impl JournalAdapter for HistoricalAdapter {
        fn template(&self) -> &'static JournalTemplate {
            recovery_template(18).unwrap()
        }
        fn read_locked(
            &self,
            permit: &BackupReadPermit<'_>,
            visitor: &mut dyn FnMut(&Connection) -> std::result::Result<(), BundleError>,
        ) -> std::result::Result<(), BundleError> {
            permit.check(self)?;
            let c = self.0.lock().unwrap();
            recovery_migration::verify_exact_schema(&c, recovery_migration::V18_SCHEMA)
                .map_err(|_| BundleError::Integrity)?;
            visitor(&c)
        }
    }
    fn files(path: &Path) -> Vec<(PathBuf, Option<Vec<u8>>)> {
        ["", "-wal", "-shm", "-journal"]
            .into_iter()
            .map(|suffix| {
                let p = PathBuf::from(format!("{}{suffix}", path.display()));
                let bytes = match std::fs::read(&p) {
                    Ok(bytes) => Some(bytes),
                    Err(error) if error.kind() == std::io::ErrorKind::NotFound => None,
                    Err(error) => panic!("cannot inspect synthetic file: {error}"),
                };
                (p, bytes)
            })
            .collect()
    }

    #[test]
    fn sealed18_is_readable_and_materialized_only_in_rollback_memory() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        let original = dir.path().join("synthetic-original18.sqlite");
        let archive = dir.path().join("synthetic-archive18.sqlite");
        let restored = dir.path().join("synthetic-restored18.sqlite");
        let original_key = DatabaseKey::from_bytes([0x61; 32]);
        let archive_key = DatabaseKey::from_bytes([0x62; 32]);
        let restored_key = DatabaseKey::from_bytes([0x63; 32]);
        let c = wholepact_storage_security::create_encrypted(&original, &original_key)
            .unwrap()
            .into_connection();
        c.execute_batch(recovery_migration::V18_SCHEMA).unwrap();
        c.pragma_update(None, "application_id", APPLICATION_ID)
            .unwrap();
        c.pragma_update(None, "user_version", 18).unwrap();
        let genesis = wholepact_authority::account_use::AccountUseGenesis {
            version: 1,
            identity: wholepact_authority::account_use::AccountUseIdentity {
                account_id: "11".repeat(32),
                full_viewing_key_digest: "22".repeat(32),
                network_profile_id: "synthetic".into(),
                derivation_domain: "dedicated-testnet-legacy-zip32-v1".into(),
            },
            witness_id: "synthetic-witness".into(),
            witness_origin_digest: "33".repeat(32),
            owner_certificate_digest: "44".repeat(32),
            native_birth_digest: "55".repeat(32),
        };
        // Historical synthetic data only; this is not a birth or native issuer.
        let account = genesis.identity.account_id.clone();
        c.execute("INSERT INTO signer_account VALUES(1,?1,7,0)", [&account])
            .unwrap();
        c.execute(
            "INSERT INTO signer_account_use_genesis VALUES(1,?1,?2,?3,?4)",
            params![
                account,
                genesis.identity.full_viewing_key_digest,
                genesis.digest().unwrap(),
                serde_json::to_string(&genesis).unwrap(),
            ],
        )
        .unwrap();
        let adapter = HistoricalAdapter(Mutex::new(c));
        let sources = [RegisteredJournal::new("signer-authority", &adapter).unwrap()];
        let gate = crate::consent_journal::tests::BackupGate;
        snapshot(SnapshotRequest {
            principal_id: "synthetic-owner",
            profile_id: "synthetic-signer-profile",
            coverage: crate::account::backup::coverage(false),
            sources: &sources,
            destination: &archive,
            key: &archive_key,
            authority: &gate,
        })
        .unwrap();
        restore(RestoreRequest {
            principal_id: "synthetic-owner",
            profile_id: "synthetic-signer-profile",
            archive: &archive,
            key: &archive_key,
            targets: &[RestoreTarget {
                component_id: "signer-authority",
                template: recovery_template(18).unwrap(),
                destination: &restored,
                key: &restored_key,
            }],
            authority: &gate,
        })
        .unwrap();
        let sealed = VerifiedSignerRecoverySource::open(
            history::HistoryOpenRequest {
                archive: &archive,
                archive_key: &archive_key,
                component_id: "signer-authority",
                restored_component: &restored,
                restored_key: &restored_key,
            },
            recovery_template(18).unwrap(),
        )
        .unwrap();
        assert_eq!(sealed.provenance().schema_version, 18);
        // An authenticated old born archive remains readable historical data,
        // but it cannot be a writable successor/implicit financial19 upgrade.
        assert!(matches!(
            require_no_old_born_recovery_source(&sealed),
            Err(JournalError::RecoveryRequired)
        ));
        assert!(!sealed
            .tables()
            .iter()
            .any(|t| t.name() == "signer_durable_payment_admission_intents"));
        let before = [files(&original), files(&archive), files(&restored)];
        with_complete_source(&sealed, |tx| {
            recovery_migration::verify_exact_schema(tx, SCHEMA)?;
            assert_eq!(storage::read_account(tx)?.writer_epoch, 7);
            assert!(!storage::read_account(tx)?.recovery_required);
            assert!(account_use_storage::inspect(tx, &account)?.genesis() == Some(&genesis));
            let empty: i64 = tx.query_row(
                "SELECT count(*) FROM signer_durable_payment_admission_intents",
                [],
                |r| r.get(0),
            )?;
            assert_eq!(empty, 0);
            Ok(())
        })
        .unwrap();
        assert!(matches!(
            super::super::require_no_old_born_recovery_source(&sealed),
            Err(JournalError::RecoveryRequired)
        ));
        let informational = QuarantinedJournalRead::from_verified(sealed, &account).unwrap();
        assert_eq!(informational.writer_epoch(), 7);
        assert!(
            before == [files(&original), files(&archive), files(&restored)],
            "sealed historical files changed"
        );
        let c = adapter.0.lock().unwrap();
        recovery_migration::verify_exact_schema(&c, recovery_migration::V18_SCHEMA).unwrap();
        assert_eq!(
            c.pragma_query_value(None, "user_version", |r| r.get::<_, i64>(0))
                .unwrap(),
            18
        );
    }
}
