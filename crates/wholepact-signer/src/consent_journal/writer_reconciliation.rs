//! Native-reviewed writer handoff imports exposure, never original consent.
use super::*;
use rusqlite::{params, OptionalExtension, TransactionBehavior};
use wholepact_authority::{
    AuthenticatedWriterSession, ReconciledAuthorityHistory, ReservationPermit,
};

struct WriterReconciliation {
    account: SignerAccountState,
    receipt: NativeConsentReceipt,
    active: AuthenticatedWriterSession,
    history: writer_history::PreparedWriterHistory,
    review_digest: String,
}
pub struct PreparedWriterReconciliation(Pending<WriterReconciliation>);
pub struct ApprovedWriterReconciliation(Approval<WriterReconciliation>);
impl PreparedWriterReconciliation {
    pub fn review_digest(&self) -> &str {
        &self.0.review_digest
    }
    /// Complete exact public identity and private exposure evidence for the
    /// trusted local window only. Contains no TLS exporter or spending key.
    pub fn display(&self) -> Result<String> {
        let _lease = self.0.session.read()?;
        let r = &self.0.record;
        let detail = if r.history.has_offline() {
            serde_json::to_string_pretty(&(
                "wholepact:signer-writer-reconciliation:v2",
                &r.account.account_id,
                r.account.writer_epoch,
                &r.receipt,
                r.active.disclosure(),
                r.active.snapshot(),
                r.active.receipt(),
                r.active.history_digest(),
                &r.history,
            ))
        } else {
            serde_json::to_string_pretty(&(
                &r.account.account_id,
                r.account.writer_epoch,
                &r.receipt,
                r.active.disclosure(),
                r.active.snapshot(),
                r.active.receipt(),
                r.active.history_digest(),
                r.history.legacy_online_permits()?,
            ))
        }
        .map_err(|_| JournalError::InvalidBinding)?;
        if detail.len() > MAX_RECORD_BYTES {
            return Err(JournalError::Limit);
        }
        Ok(format!(
            "Reconcile signer writer authority\n\nLocal epoch: {}\nOwner-activated witness epoch: {}\nRemote reservations retained: {}\nRemote outstanding debit: {} zatoshis\n\nEvery remote reservation below remains conservative outstanding exposure, including expired permits. No original consent is created or renewed. Existing originals and release uncertainty remain unchanged. This cannot clear recovery quarantine. An epoch change requires a fresh native session and new enrollment/review before spending.\n\nExact reviewed account, old epoch, native receipt, witness identity, full history head/state, activated client receipt, history digest and all reservation descriptors:\n{}",
            r.account.writer_epoch,
            r.active.snapshot().writer_epoch,
            r.history.len(),
            r.active.snapshot().outstanding_debit_zatoshis,
            detail
        ))
    }
    pub fn writer_epoch(&self) -> u64 {
        self.0.record.active.snapshot().writer_epoch
    }
    pub fn reservation_count(&self) -> usize {
        self.0.record.history.len()
    }
    pub fn outstanding_debit_zatoshis(&self) -> u64 {
        self.0.record.active.snapshot().outstanding_debit_zatoshis
    }
}
impl SignerConsentSession {
    /// Only complete authenticated history and this live client's independently
    /// owner-activated session can propose an epoch transition. Raw snapshots
    /// and serialized receipts have no conversion to this operation.
    pub fn prepare_writer_reconciliation(
        &self,
        journal: &SignerConsentJournal,
        history: ReconciledAuthorityHistory,
        active: AuthenticatedWriterSession,
    ) -> Result<PreparedWriterReconciliation> {
        let account = journal.account_state()?;
        let lease = self.read_lease(&journal.binding(), &account)?;
        lease.check_current()?;
        if account.recovery_required {
            return Err(JournalError::RecoveryRequired);
        }
        let snapshot = active.snapshot();
        if history.snapshot() != snapshot
            || history.disclosure() != active.disclosure()
            || history
                .history_digest()
                .map_err(|_| JournalError::InvalidBinding)?
                != active.history_digest()
            || snapshot.account_id != account.account_id
            || snapshot.writer_epoch < account.writer_epoch
            || snapshot.writer_epoch > i64::MAX as u64
            || snapshot.active_writer_session.as_ref() != Some(active.receipt())
            || active.receipt().writer_epoch != snapshot.writer_epoch
            || active.receipt().disclosure != *active.disclosure()
            || now_ms()? >= active.receipt().expires_at_ms
        {
            return Err(JournalError::InvalidBinding);
        }
        let retained = {
            let mut c = journal
                .connection
                .lock()
                .map_err(|_| JournalError::Database)?;
            let tx = c.transaction_with_behavior(TransactionBehavior::Deferred)?;
            let local = writer_history::WriterLocalInventory::read(
                &tx,
                &account,
                journal.capacity_limits(),
            )?;
            let prepared = writer_history::PreparedWriterHistory::prepare(&local, &history)?;
            // Offline preparation remains unavailable until EVERY downstream
            // recovery, host IPC and intake consumer is coherently qualified.
            prepared.require_enabled()?;
            offline_history::require_legacy_journal(&tx)?;
            lease.check_current()?;
            if now_ms()? >= active.receipt().expires_at_ms {
                return Err(JournalError::Expired);
            }
            tx.rollback()?;
            prepared
        };
        let receipt = self.receipt()?;
        let review_digest = if retained.has_offline() {
            digest(
                "wholepact:signer-writer-reconciliation:v2",
                &(
                    &account.account_id,
                    account.writer_epoch,
                    &receipt,
                    active.disclosure(),
                    snapshot,
                    active.receipt(),
                    active.history_digest(),
                    &retained,
                ),
            )?
        } else {
            // Original tuple, domain, vector order and optional-field omission.
            digest(
                "wholepact:signer-writer-reconciliation:v1",
                &(
                    &account.account_id,
                    account.writer_epoch,
                    &receipt,
                    active.disclosure(),
                    snapshot,
                    active.receipt(),
                    active.history_digest(),
                    retained.legacy_online_permits()?,
                ),
            )?
        };
        let record = WriterReconciliation {
            account,
            receipt,
            active,
            history: retained,
            review_digest: review_digest.clone(),
        };
        Ok(PreparedWriterReconciliation(Pending::new(
            record,
            review_digest,
            &self.inner,
        )))
    }
    pub fn approve_writer_reconciliation(
        &self,
        prepared: PreparedWriterReconciliation,
        decision: NativeConsentDecision,
    ) -> Result<ApprovedWriterReconciliation> {
        Ok(ApprovedWriterReconciliation(
            prepared.0.approve(self, decision)?,
        ))
    }
}
impl SignerConsentJournal {
    /// Atomic handoff. Existing originals, release uncertainty and quarantine
    /// remain unchanged. Epoch advancement expires all old local session leases;
    /// fresh native enrollment/consent is still required for subsequent spending.
    pub fn reconcile_writer(
        &self,
        approved: ApprovedWriterReconciliation,
    ) -> Result<SignerAccountState> {
        let a = approved.0;
        let r = &a.record;
        let lease = a.lease(&self.binding(), &r.account, &r.receipt)?;
        let _fence = self
            .authority_fence
            .write()
            .map_err(|_| JournalError::Permission)?;
        let mut connection = self.connection.lock().map_err(|_| JournalError::Database)?;
        let tx = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        storage::check_account(&tx, &r.account)?;
        // Refuse before ANY mutation. This gate is also enforced by the import
        // kernel so offline plans cannot accidentally bypass it internally.
        r.history.require_enabled()?;
        offline_history::require_legacy_journal(&tx)?;
        let local =
            writer_history::WriterLocalInventory::read(&tx, &r.account, self.capacity_limits())?;
        r.history.require_unchanged_local(&local)?;
        if now_ms()? >= r.active.receipt().expires_at_ms {
            return Err(JournalError::Expired);
        }
        let snapshot = r.active.snapshot();
        let disclosure = encode(r.active.disclosure())?;
        let latest: Option<(String,u64,String)> = tx.query_row(
            "SELECT disclosure,head_sequence,head_digest FROM signer_writer_reconciliations ORDER BY head_sequence DESC LIMIT 1", [],
            |row| Ok((row.get(0)?,row.get(1)?,row.get(2)?)),
        ).optional()?;
        if let Some((old, sequence, head)) = latest {
            if old != *disclosure
                || snapshot.head.sequence < sequence
                || (snapshot.head.sequence == sequence && snapshot.head.digest != head)
            {
                return Err(JournalError::Conflict);
            }
        }
        r.history.import_enabled(&tx, &r.account.account_id)?;
        let payload = encode(&(r.active.receipt(), &r.receipt, r.active.history_digest()))?;
        tx.execute(
            "INSERT OR IGNORE INTO signer_writer_reconciliations VALUES(?1,?2,?3,?4,?5,?6)",
            params![
                r.review_digest,
                disclosure.as_str(),
                snapshot.head.sequence,
                snapshot.head.digest,
                snapshot.writer_epoch,
                payload.as_str()
            ],
        )?;
        tx.execute(
            "UPDATE signer_account SET writer_epoch=?1 WHERE singleton=1",
            [snapshot.writer_epoch],
        )?;
        storage::bounded(&tx, self.capacity_limits())?;
        lease.check_current()?;
        if now_ms()? >= r.active.receipt().expires_at_ms {
            return Err(JournalError::Expired);
        }
        tx.commit()?;
        Ok(SignerAccountState {
            account_id: r.account.account_id.clone(),
            writer_epoch: snapshot.writer_epoch,
            recovery_required: r.account.recovery_required,
        })
    }
}
pub(in crate::consent_journal) fn retain_remote_exposure(
    c: &rusqlite::Connection,
    permit: &ReservationPermit,
    account: &str,
) -> Result<()> {
    let request = &permit.request;
    permit
        .matches_request(request)
        .map_err(|_| JournalError::InvalidBinding)?;
    request
        .validate()
        .map_err(|_| JournalError::InvalidBinding)?;
    if request.account_id != account {
        return Err(JournalError::InvalidBinding);
    }
    let raw = encode(permit)?;
    let old: Option<String> = c
        .query_row(
            "SELECT payload FROM signer_remote_exposures WHERE authorization_id=?1",
            [&request.authorization_id],
            |r| r.get(0),
        )
        .optional()?;
    if let Some(old) = old {
        if old != *raw {
            return Err(JournalError::Conflict);
        }
        return Ok(());
    }
    let local: Option<String> = c.query_row("SELECT payload FROM signer_original_consents WHERE authorization_id=?1 OR reference=?2", params![request.authorization_id,request.original_consent_ref], |r| r.get(0)).optional()?;
    if let Some(local) = local {
        let original: OriginalSpendConsent = decode(local)?;
        original.validate()?;
        let retained = storage::read_original(c, &original.terms().authorization_id)?
            .ok_or(JournalError::InvalidBinding)?;
        if retained.original_consent() != &original {
            return Err(JournalError::Conflict);
        }
        writer_history::validate_original_permit(&retained, permit)?;
    }
    c.execute(
        "INSERT INTO signer_remote_exposures VALUES(?1,?2,?3,?4,?5,?6)",
        params![
            request.authorization_id,
            request.original_consent_ref,
            account,
            request.obligation_id,
            request.maximum_debit_zatoshis.to_string(),
            raw.as_str()
        ],
    )?;
    for input in &request.inputs {
        c.execute(
            "INSERT INTO signer_remote_inputs VALUES(?1,?2,?3)",
            params![request.authorization_id, account, input.nullifier],
        )?;
    }
    Ok(())
}
