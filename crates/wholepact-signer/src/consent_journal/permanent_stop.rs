//! Restriction-only durable boundary. Local exclusion precedes remote work and
//! shares the exclusive fence with authorization admission. No exposure row is
//! changed, no quarantine is cleared, and no absent genesis is synthesized.
use super::*;
#[path = "permanent_stop_local_cells.rs"]
mod local_cells;
/// Reuse the full maintained online-ledger verifier without performing any
/// permanent-stop mutation or interpreting its result as current authority.
#[cfg(feature = "durable-proposal")]
pub(super) fn validate_retained_local_cells(
    connection: &rusqlite::Connection,
    account: &SignerAccountState,
    limits: (u64, u64),
) -> Result<()> {
    local_cells::validate(connection, account, limits).map(|_| ())
}
use crate::account::birth::enrollment::roster_v2::permanent_stop::{
    LocalPermanentStopPublication, PermanentStopHistoryPin, PermanentStopWitnessAcknowledgment,
};
use rusqlite::TransactionBehavior;
use std::collections::BTreeMap;
use wholepact_authority::account_use::{AccountUseGenesis, PermanentAccountExclusion};
use wholepact_authority::account_use_link::AccountExclusionReceipt;

#[derive(Clone, PartialEq, Eq, Serialize)]
pub(crate) struct PermanentStopSnapshot {
    pub(crate) genesis: AccountUseGenesis,
    pub(crate) exclusion: Option<PermanentAccountExclusion>,
    pub(crate) witness_ack: Option<AccountExclusionReceipt>,
    pub(crate) writer_epoch: u64,
    pub(crate) recovery_required: bool,
    /// Every retained ledger table remains present. Counts are not a balance or
    /// an assertion that no external authorization exists.
    pub(crate) journal_commitment: String,
    pub(crate) retained_rows: BTreeMap<String, u64>,
}
fn snapshot(
    c: &rusqlite::Connection,
    genesis: &AccountUseGenesis,
) -> Result<PermanentStopSnapshot> {
    storage::verify_schema(c)?;
    let account = storage::read_account(c)?;
    let use_state = account_use_storage::inspect(c, &account.account_id)?;
    if account.account_id != genesis.identity.account_id || use_state.genesis() != Some(genesis) {
        return Err(JournalError::InvalidBinding);
    }
    let retained_rows = retained_table_counts(c)?;
    Ok(PermanentStopSnapshot {
        genesis: genesis.clone(),
        exclusion: use_state.exclusion().cloned(),
        witness_ack: use_state.witness_ack().cloned(),
        writer_epoch: account.writer_epoch,
        recovery_required: account.recovery_required,
        journal_commitment: writer_history::complete_journal_commitment(c)?,
        retained_rows,
    })
}
fn retained_table_counts(c: &rusqlite::Connection) -> Result<BTreeMap<String, u64>> {
    let mut q = c.prepare("SELECT name FROM sqlite_schema WHERE type='table' AND name NOT LIKE 'sqlite_%' ORDER BY name")?;
    let names = q
        .query_map([], |r| r.get::<_, String>(0))?
        .collect::<std::result::Result<Vec<_>, _>>()?;
    let mut retained_rows = BTreeMap::new();
    for name in names {
        // Identifiers originate only in the executable-verified exact schema.
        let count = c.query_row(
            &format!("SELECT count(*) FROM \"{}\"", name.replace('"', "\"\"")),
            [],
            |r| r.get(0),
        )?;
        retained_rows.insert(name, count);
    }
    Ok(retained_rows)
}

impl SignerConsentJournal {
    pub(crate) fn permanent_stop_local_review(
        &self,
        genesis: &AccountUseGenesis,
    ) -> Result<(PermanentStopSnapshot, serde_json::Value)> {
        let _fence = self
            .authority_fence
            .try_write()
            .map_err(|_| JournalError::Permission)?;
        let mut c = self.connection.lock().map_err(|_| JournalError::Database)?;
        let tx = c.transaction_with_behavior(TransactionBehavior::Deferred)?;
        let state = snapshot(&tx, genesis)?;
        let account = storage::read_account(&tx)?;
        let mut display = writer_history::validate_permanent_stop_archive_cells(
            &tx,
            &account,
            self.capacity_limits(),
        )?;
        let cells = local_cells::validate(&tx, &account, self.capacity_limits())?;
        display
            .as_object_mut()
            .ok_or(JournalError::InvalidBinding)?
            .insert("typed_local_history".into(), cells);
        if serde_json::to_vec(&display)
            .map_err(|_| JournalError::InvalidBinding)?
            .len()
            > 2 * 1024 * 1024
        {
            return Err(JournalError::Limit);
        }
        tx.commit()?;
        Ok((state, display))
    }
    pub(crate) fn permanent_stop_snapshot(
        &self,
        genesis: &AccountUseGenesis,
    ) -> Result<PermanentStopSnapshot> {
        let _fence = self
            .authority_fence
            .try_write()
            .map_err(|_| JournalError::Permission)?;
        let mut c = self.connection.lock().map_err(|_| JournalError::Database)?;
        let tx = c.transaction_with_behavior(TransactionBehavior::Deferred)?;
        storage::bounded(&tx, self.capacity_limits())?;
        let state = snapshot(&tx, genesis)?;
        tx.commit()?;
        Ok(state)
    }
    pub(crate) fn retain_permanent_stop(
        &self,
        publication: &LocalPermanentStopPublication<'_>,
    ) -> Result<PermanentStopSnapshot> {
        publication
            .check_current(self)
            .map_err(|_| JournalError::Permission)?;
        let _fence = self
            .authority_fence
            .try_write()
            .map_err(|_| JournalError::Permission)?;
        let mut c = self.connection.lock().map_err(|_| JournalError::Database)?;
        let tx = c.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let before = snapshot(&tx, publication.genesis())?;
        if &before != publication.expected_snapshot() {
            return Err(JournalError::Conflict);
        }
        account_use_storage::append_exclusion(
            &tx,
            &publication.genesis().identity.account_id,
            publication.exclusion(),
        )?;
        storage::bounded(&tx, self.capacity_limits())?;
        let after = snapshot(&tx, publication.genesis())?;
        publication
            .check_current(self)
            .map_err(|_| JournalError::Permission)?;
        tx.commit()?;
        Ok(after)
    }
    pub(crate) fn retain_permanent_stop_witness_ack(
        &self,
        publication: &PermanentStopWitnessAcknowledgment<'_>,
    ) -> Result<()> {
        publication
            .check_current(self)
            .map_err(|_| JournalError::Permission)?;
        let _fence = self
            .authority_fence
            .try_write()
            .map_err(|_| JournalError::Permission)?;
        let mut c = self.connection.lock().map_err(|_| JournalError::Database)?;
        let tx = c.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let before = snapshot(&tx, publication.genesis())?;
        if &before != publication.expected_snapshot() {
            return Err(JournalError::Conflict);
        }
        account_use_storage::append_witness_ack(
            &tx,
            &publication.genesis().identity.account_id,
            publication.receipt(),
        )?;
        storage::bounded(&tx, self.capacity_limits())?;
        publication
            .check_current(self)
            .map_err(|_| JournalError::Permission)?;
        tx.commit()?;
        Ok(())
    }
}

impl SignerConsentJournal {
    /// Complete historical validation for restrictive publication only. Pending
    /// local exclusion is the sole permitted projection asymmetry; no writer,
    /// recovery, financial or generalized history capability is returned.
    pub(crate) fn permanent_stop_complete_history(
        &self,
        pin: &PermanentStopHistoryPin<'_>,
    ) -> Result<(PermanentStopSnapshot, serde_json::Value)> {
        pin.check_current(self)
            .map_err(|_| JournalError::Permission)?;
        let result = self.permanent_stop_historical_cells(pin.genesis(), pin.history())?;
        if result.0.writer_epoch != pin.epoch() {
            return Err(JournalError::Conflict);
        }
        pin.check_current(self)
            .map_err(|_| JournalError::Permission)?;
        Ok(result)
    }
    fn permanent_stop_historical_cells(
        &self,
        genesis: &AccountUseGenesis,
        history: &wholepact_authority::ReconciledAuthorityHistory,
    ) -> Result<(PermanentStopSnapshot, serde_json::Value)> {
        let _fence = self
            .authority_fence
            .try_write()
            .map_err(|_| JournalError::Permission)?;
        let mut c = self.connection.lock().map_err(|_| JournalError::Database)?;
        let tx = c.transaction_with_behavior(TransactionBehavior::Deferred)?;
        let state = snapshot(&tx, genesis)?;
        if history.account_use_history().genesis() != Some(genesis)
            || history.snapshot().account_id != genesis.identity.account_id
            || history.snapshot().writer_epoch != state.writer_epoch
        {
            return Err(JournalError::InvalidBinding);
        }
        match (&state.exclusion, history.account_use_history().exclusion()) {
            (Some(local), Some(remote)) if local != remote => return Err(JournalError::Conflict),
            (None, Some(_)) => return Err(JournalError::RecoveryRequired),
            _ => {}
        }
        if let Some(ack) = &state.witness_ack {
            let exclusion = state
                .exclusion
                .as_ref()
                .ok_or(JournalError::InvalidBinding)?;
            let actual =
                wholepact_authority::account_use_link::reconcile_account_exclusion_complete(
                    history,
                    genesis,
                    history.disclosure(),
                    exclusion,
                )
                .map_err(|_| JournalError::InvalidBinding)?;
            if actual.evidence() != ack {
                return Err(JournalError::Conflict);
            }
        }
        let account = storage::read_account(&tx)?;
        let cells = local_cells::validate(&tx, &account, self.capacity_limits())?;
        let source = writer_history::TransportContinuityLocalInventory::read(
            &tx,
            &account,
            self.capacity_limits(),
            history,
        )?;
        source.validate_financial_origins(history)?;
        offline_receipts::validate_transport_reconciled(
            &tx,
            &account.account_id,
            history,
            source.construction(),
        )?;
        let union = source
            .local()
            .offline_history()
            .reconcile_transport_financial_branch(history, source.construction())?;
        union.require_retained_offline_coverage()?;
        let online = union
            .witness_online_reservations()
            .iter()
            .map(|permit| (*permit).clone())
            .collect::<Vec<_>>();
        // Complete bridge, sponsor, automation and historical writer linkage.
        // A journal-local witness pin is optional ONLY here: the public wrapper
        // holds the exact immutable original born-source pin independently.
        host_recovery_continuity::validate_online_continuity_cells(&tx, history, &online)?;
        let offline = union
            .offline_origins()
            .iter()
            .map(|o| {
                serde_json::json!({
                    "terms": o.terms(), "presence": format!("{:?}", o.presence()),
                    "signature_knowledge": format!("{:?}", o.signature_knowledge()),
                    "replayed_writer_epoch": o.replayed_writer_epoch(),
                })
            })
            .collect::<Vec<_>>();
        // The financial-only branch intentionally excludes construction. Add
        // the complete transport-aware retained charge exactly once, as in V5.
        let financial_debit = union.conservative_union_debit_zatoshis()?;
        let construction_debit = source
            .construction()
            .retained_debit_zatoshis()
            .map_err(|_| JournalError::InvalidBinding)?;
        let complete_debit = financial_debit
            .checked_add(construction_debit)
            .ok_or(JournalError::Limit)?;
        let display = serde_json::json!({
            "purpose": "restriction_only_complete_historical_observation",
            "typed_local_history": cells,
            "witness_facts": history.retirement_history_facts().map_err(|_| JournalError::InvalidBinding)?,
            "online_reservations_including_resolved": union.witness_online_reservations(),
            "offline_origins": offline,
            "offline_enrollments": union.retained_enrollments(),
            "offline_reservation_intents": union.retained_reservation_intents(),
            "conservative_historical_union_debit_zatoshis": complete_debit,
            "historical_financial_and_offline_debit_zatoshis": financial_debit,
            "retained_construction_and_transport_debit_zatoshis": construction_debit,
            "construction_and_transport_history": source.construction(),
            "retained_common_context_history": source.audit(),
            "complete_local_journal_commitment": source.local().commitment(),
            "witness_history_digest": history.history_digest().map_err(|_| JournalError::InvalidBinding)?,
            "notice": "All historical descriptors remain conservative exposure. This is not balance, canonical unspentness, account emptiness, or proof that no external signatures exist. A pending local tombstone cannot authorize recovery or key use."
        });
        if serde_json::to_vec(&display)
            .map_err(|_| JournalError::InvalidBinding)?
            .len()
            > 2 * 1024 * 1024
        {
            return Err(JournalError::Limit);
        }
        drop(union);
        tx.commit()?;
        Ok((state, display))
    }
}

impl SignerConsentJournal {
    /// Read-only archival recognition of an already restricted born journal.
    /// All ciphertext/cells remain intact. This cannot establish current witness
    /// agreement, enrollment, readiness or any recovery/financial capability.
    pub(crate) fn verify_permanent_stop_archive(
        path: &std::path::Path,
        key: &wholepact_storage_security::DatabaseKey,
        genesis: &AccountUseGenesis,
    ) -> Result<PermanentStopSnapshot> {
        let current = wholepact_storage_security::bundle::open_journal_read_snapshot(
            path,
            key,
            &storage::TEMPLATE,
        );
        if let Ok(read) = current {
            let state = validate_archive_snapshot(read.connection(), genesis)?;
            read.check_source_unchanged()?;
            return Ok(state);
        }
        // Exact frozen18 is a historical reader, never an original-file upgrade.
        // Do not omit its stopped rows merely because current capacity adds a table.
        let read = wholepact_storage_security::bundle::open_journal_read_snapshot(
            path,
            key,
            recovery_activation::recovery_template(18)?,
        )
        .map_err(|_| JournalError::InvalidBinding)?;
        let c = read.connection();
        let mut state = with_complete_frozen18(c, |tx| validate_archive_snapshot(tx, genesis))?;
        // Retain the ORIGINAL18 inventory/commitment, not the additive memory view.
        state.retained_rows = retained_table_counts(c)?;
        state.journal_commitment = writer_history::complete_journal_commitment(c)?;
        read.check_source_unchanged()?;
        Ok(state)
    }
}

fn validate_archive_snapshot(
    c: &rusqlite::Connection,
    genesis: &AccountUseGenesis,
) -> Result<PermanentStopSnapshot> {
    let state = snapshot(c, genesis)?;
    if state.exclusion.is_none() {
        return Err(JournalError::InvalidBinding);
    }
    let account = storage::read_account(c)?;
    writer_history::validate_permanent_stop_archive_cells(
        c,
        &account,
        (MAX_BACKUP_ROWS, MAX_BACKUP_ENCODED_BYTES),
    )?;
    local_cells::validate(c, &account, (MAX_BACKUP_ROWS, MAX_BACKUP_ENCODED_BYTES))?;
    Ok(state)
}

/// Isolated rollback-only additive DATA view. No writable original, source
/// relabel, runtime owner, approval, or migration route can escape this helper.
fn with_complete_frozen18<T>(
    original: &rusqlite::Connection,
    inspect: impl FnOnce(&rusqlite::Transaction<'_>) -> Result<T>,
) -> Result<T> {
    use rusqlite::{
        params_from_iter,
        types::{Value, ValueRef},
        Connection,
    };
    let application: i64 = original.pragma_query_value(None, "application_id", |r| r.get(0))?;
    let version: i64 = original.pragma_query_value(None, "user_version", |r| r.get(0))?;
    if application != APPLICATION_ID || version != 18 {
        return Err(JournalError::UnsupportedSchema);
    }
    recovery_migration::verify_exact_schema(original, recovery_migration::V18_SCHEMA)?;
    let mut memory = Connection::open_in_memory()?;
    memory.execute_batch("PRAGMA foreign_keys=ON; PRAGMA temp_store=MEMORY;")?;
    let tx = memory.transaction_with_behavior(TransactionBehavior::Deferred)?;
    tx.execute_batch(SCHEMA)?;
    tx.execute_batch("PRAGMA defer_foreign_keys=ON;")?;
    let mut names =
        original.prepare("SELECT name FROM sqlite_schema WHERE type='table' ORDER BY name")?;
    let tables = names
        .query_map([], |r| r.get::<_, String>(0))?
        .collect::<std::result::Result<Vec<_>, _>>()?;
    drop(names);
    let mut count = 0_u64;
    let mut text_bytes = 0_u64;
    for table in tables {
        let quoted = table.replace('"', "\"\"");
        let mut statement =
            original.prepare(&format!("SELECT rowid,* FROM \"{quoted}\" ORDER BY rowid"))?;
        let width = statement.column_count();
        let columns = statement
            .column_names()
            .iter()
            .skip(1)
            .map(|name| format!("\"{}\"", name.replace('"', "\"\"")))
            .collect::<Vec<_>>();
        let sql = format!(
            "INSERT INTO \"{quoted}\"(rowid,{}) VALUES({})",
            columns.join(","),
            vec!["?"; width].join(",")
        );
        let mut rows = statement.query([])?;
        while let Some(row) = rows.next()? {
            count = count.checked_add(1).ok_or(JournalError::Limit)?;
            if count > MAX_BACKUP_ROWS {
                return Err(JournalError::Limit);
            }
            let mut values = Vec::with_capacity(width);
            for index in 0..width {
                values.push(match row.get_ref(index)? {
                    ValueRef::Null if index != 0 => Value::Null,
                    ValueRef::Integer(value) => Value::Integer(value),
                    ValueRef::Text(bytes) if index != 0 => {
                        if bytes.len() > 4 * 1024 * 1024 {
                            return Err(JournalError::Limit);
                        }
                        text_bytes = text_bytes
                            .checked_add(bytes.len() as u64)
                            .ok_or(JournalError::Limit)?;
                        let upper = text_bytes
                            .checked_mul(6)
                            .and_then(|n| {
                                count
                                    .checked_mul(2048)
                                    .and_then(|overhead| n.checked_add(overhead))
                            })
                            .ok_or(JournalError::Limit)?;
                        if upper > MAX_BACKUP_ENCODED_BYTES {
                            return Err(JournalError::Limit);
                        }
                        Value::Text(
                            std::str::from_utf8(bytes)
                                .map_err(|_| JournalError::InvalidBinding)?
                                .to_owned(),
                        )
                    }
                    _ => return Err(JournalError::InvalidBinding),
                });
            }
            tx.execute(&sql, params_from_iter(values))?;
        }
    }
    storage::bounded(&tx, (MAX_BACKUP_ROWS, MAX_BACKUP_ENCODED_BYTES))?;
    let foreign_keys: i64 =
        tx.query_row("SELECT count(*) FROM pragma_foreign_key_check", [], |r| {
            r.get(0)
        })?;
    let added: i64 = tx.query_row(
        "SELECT count(*) FROM signer_durable_payment_admission_intents",
        [],
        |r| r.get(0),
    )?;
    if foreign_keys != 0 || added != 0 {
        return Err(JournalError::InvalidBinding);
    }
    let result = inspect(&tx)?;
    tx.rollback()?;
    Ok(result)
}

#[cfg(test)]
impl SignerConsentJournal {
    /// Synthetic recorded-history data reader only. Never constructs the sealed
    /// original born-source pin or any native/publication authority.
    pub(super) fn permanent_stop_synthetic_history(
        &self,
        genesis: &AccountUseGenesis,
        history: &wholepact_authority::ReconciledAuthorityHistory,
    ) -> Result<(PermanentStopSnapshot, serde_json::Value)> {
        self.permanent_stop_historical_cells(genesis, history)
    }
}

#[cfg(test)]
mod frozen18_archive_tests {
    use super::*;
    use rusqlite::{params, Connection};
    use std::{fs, os::unix::fs::PermissionsExt, path::PathBuf};
    use wholepact_authority::account_use::{AccountUseIdentity, ExclusionReason};
    use wholepact_storage_security::DatabaseKey;

    struct Fixture {
        connection: Connection,
        _directory: crate::files::PrivateDirectory,
        _temp: tempfile::TempDir,
        path: PathBuf,
        key: DatabaseKey,
        genesis: AccountUseGenesis,
        exclusion: PermanentAccountExclusion,
        ack: AccountExclusionReceipt,
    }
    impl Fixture {
        fn new(corrupt_stop: bool, unknown_exposure: bool) -> Self {
            let temp = tempfile::tempdir().unwrap();
            fs::set_permissions(temp.path(), fs::Permissions::from_mode(0o700)).unwrap();
            let directory = crate::files::PrivateDirectory::open(temp.path()).unwrap();
            let path = temp.path().join("stopped18.sqlite");
            let key = DatabaseKey::from_bytes([182; 32]);
            let c = wholepact_storage_security::create_encrypted(&path, &key)
                .unwrap()
                .into_connection();
            c.execute_batch("PRAGMA journal_mode=WAL; PRAGMA wal_autocheckpoint=0;")
                .unwrap();
            c.execute_batch(recovery_migration::V18_SCHEMA).unwrap();
            c.pragma_update(None, "application_id", APPLICATION_ID)
                .unwrap();
            c.pragma_update(None, "user_version", 18).unwrap();
            let genesis = AccountUseGenesis {
                version: 1,
                identity: AccountUseIdentity {
                    account_id: "11".repeat(32),
                    full_viewing_key_digest: "22".repeat(32),
                    network_profile_id: "synthetic-stopped-archive".into(),
                    derivation_domain: "dedicated-testnet-legacy-zip32-v1".into(),
                },
                witness_id: "synthetic-witness-no-service".into(),
                witness_origin_digest: "33".repeat(32),
                owner_certificate_digest: "44".repeat(32),
                native_birth_digest: "55".repeat(32),
            };
            let exclusion = PermanentAccountExclusion {
                version: 1,
                identity: genesis.identity.clone(),
                genesis_digest: genesis.digest().unwrap(),
                operation_id: "synthetic-stop18".into(),
                native_review_digest: "66".repeat(32),
                reason: ExclusionReason::RetirementRequested,
            };
            let ack = AccountExclusionReceipt {
                genesis_digest: genesis.digest().unwrap(),
                exclusion_digest: exclusion.digest().unwrap(),
                witness_origin_digest: genesis.witness_origin_digest.clone(),
                committed_head: wholepact_authority::AuthorityHead {
                    sequence: 2,
                    digest: "77".repeat(32),
                },
                operation_id: exclusion.operation_id.clone(),
            };
            c.execute(
                "INSERT INTO signer_account VALUES(1,?1,7,1)",
                [&genesis.identity.account_id],
            )
            .unwrap();
            c.execute(
                "INSERT INTO signer_account_use_genesis VALUES(1,?1,?2,?3,?4)",
                params![
                    genesis.identity.account_id,
                    genesis.identity.full_viewing_key_digest,
                    genesis.digest().unwrap(),
                    encode(&genesis).unwrap().as_str()
                ],
            )
            .unwrap();
            let mut stop_payload = exclusion.clone();
            if corrupt_stop {
                stop_payload.genesis_digest = "88".repeat(32);
            }
            c.execute(
                "INSERT INTO signer_account_use_exclusion VALUES(1,?1,?2,?3)",
                params![
                    exclusion.genesis_digest,
                    exclusion.digest().unwrap(),
                    encode(&stop_payload).unwrap().as_str()
                ],
            )
            .unwrap();
            // Historical DTO only, not a fabricated ReconciledAccountExclusion.
            c.execute("INSERT INTO signer_account_use_witness_ack(rowid,exclusion_digest,witness_origin_digest,committed_head_digest,receipt_digest,payload) VALUES(71,?1,?2,?3,?4,?5)",params![ack.exclusion_digest,ack.witness_origin_digest,ack.committed_head.digest,ack.digest().unwrap(),encode(&ack).unwrap().as_str()]).unwrap();
            if unknown_exposure {
                c.execute("INSERT INTO signer_remote_exposures VALUES('unknown-authorization','unknown-original',?1,'unknown-obligation','1','{}')",[&genesis.identity.account_id]).unwrap();
            }
            Self {
                connection: c,
                _directory: directory,
                _temp: temp,
                path,
                key,
                genesis,
                exclusion,
                ack,
            }
        }
        fn files(&self) -> BTreeMap<PathBuf, Vec<u8>> {
            fs::read_dir(self.path.parent().unwrap())
                .unwrap()
                .map(|entry| {
                    let path = entry.unwrap().path();
                    let bytes = fs::read(&path).unwrap();
                    (path, bytes)
                })
                .collect()
        }
    }

    #[test]
    fn exact_stopped18_preserves_original_commitment_rowids_stop_ack_and_all_files() {
        let f = Fixture::new(false, false);
        let commitment = writer_history::complete_journal_commitment(&f.connection).unwrap();
        let counts = retained_table_counts(&f.connection).unwrap();
        let before = f.files();
        let read = wholepact_storage_security::bundle::open_journal_read_snapshot(
            &f.path,
            &f.key,
            recovery_activation::recovery_template(18).unwrap(),
        )
        .unwrap();
        with_complete_frozen18(read.connection(), |tx| {
            assert_eq!(
                tx.query_row(
                    "SELECT rowid FROM signer_account_use_witness_ack",
                    [],
                    |r| r.get::<_, i64>(0)
                )?,
                71
            );
            assert_eq!(
                tx.query_row(
                    "SELECT count(*) FROM signer_durable_payment_admission_intents",
                    [],
                    |r| r.get::<_, i64>(0)
                )?,
                0
            );
            Ok(())
        })
        .unwrap();
        let state =
            SignerConsentJournal::verify_permanent_stop_archive(&f.path, &f.key, &f.genesis)
                .unwrap();
        assert!(state.exclusion.as_ref() == Some(&f.exclusion));
        assert!(state.witness_ack.as_ref() == Some(&f.ack));
        assert_eq!(state.writer_epoch, 7);
        assert!(state.recovery_required);
        assert_eq!(state.journal_commitment, commitment);
        assert_eq!(state.retained_rows, counts);
        assert!(!state
            .retained_rows
            .contains_key("signer_durable_payment_admission_intents"));
        assert!(
            before == f.files(),
            "frozen stopped18 source or sidecars changed"
        );
        assert_eq!(
            f.connection
                .pragma_query_value(None, "user_version", |r| r.get::<_, i64>(0))
                .unwrap(),
            18
        );
    }

    #[test]
    fn stopped18_substituted_genesis_corrupt_stop_unknown_exposure_or_key_refuses_unchanged() {
        for (corrupt_stop, unknown_exposure) in [(false, false), (true, false), (false, true)] {
            let f = Fixture::new(corrupt_stop, unknown_exposure);
            let before = f.files();
            let mut wrong = f.genesis.clone();
            wrong.identity.full_viewing_key_digest = "99".repeat(32);
            assert!(
                SignerConsentJournal::verify_permanent_stop_archive(&f.path, &f.key, &wrong)
                    .is_err()
            );
            assert!(SignerConsentJournal::verify_permanent_stop_archive(
                &f.path,
                &DatabaseKey::from_bytes([183; 32]),
                &f.genesis
            )
            .is_err());
            if corrupt_stop || unknown_exposure {
                assert!(SignerConsentJournal::verify_permanent_stop_archive(
                    &f.path, &f.key, &f.genesis
                )
                .is_err());
            }
            assert!(
                before == f.files(),
                "denied frozen stopped18 source or sidecars changed"
            );
        }
    }
}
