//! Restriction-only durable boundary. Local exclusion precedes remote work and
//! shares the exclusive fence with authorization admission. No exposure row is
//! changed, no quarantine is cleared, and no absent genesis is synthesized.
use super::*;
#[path = "permanent_stop_local_cells.rs"]
mod local_cells;
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
        let read = wholepact_storage_security::bundle::open_journal_read_snapshot(
            path,
            key,
            &storage::TEMPLATE,
        )
        .map_err(|_| JournalError::InvalidBinding)?;
        let c = read.connection();
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
