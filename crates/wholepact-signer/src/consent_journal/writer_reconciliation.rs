//! Native-reviewed writer handoff imports exposure, never original consent.
use super::*;
use rusqlite::{params, OptionalExtension, TransactionBehavior};
use wholepact_authority::{
    AuthenticatedWriterSession, ReconciledAuthorityHistory, ReservationPermit,
};

// Purpose is minted only by the corresponding complete-history constructor.
// Legacy review domains and serialization continue to use the inner old value.
enum WriterHistory {
    Legacy(writer_history::PreparedWriterHistory),
    Durable(writer_history::PreparedDurableWriterHistoryV1),
}
impl WriterHistory {
    fn len(&self) -> usize {
        match self {
            Self::Legacy(v) => v.len(),
            Self::Durable(v) => v.len(),
        }
    }
    fn has_offline(&self) -> bool {
        matches!(self, Self::Legacy(v) if v.has_offline())
    }
    fn legacy_online_permits(&self) -> Result<&[ReservationPermit]> {
        match self {
            Self::Legacy(v) => v.legacy_online_permits(),
            Self::Durable(_) => Err(JournalError::RecoveryRequired),
        }
    }
    fn require_supported(
        &self,
        tx: &rusqlite::Connection,
        account: &SignerAccountState,
        limits: (u64, u64),
    ) -> Result<()> {
        match self {
            Self::Legacy(v) => {
                v.require_enabled()?;
                offline_history::require_legacy_journal(tx)
            }
            Self::Durable(v) => v.require_supported_local(tx, account, limits),
        }
    }
    fn require_unchanged_local(&self, local: &writer_history::WriterLocalInventory) -> Result<()> {
        match self {
            Self::Legacy(v) => v.require_unchanged_local(local),
            Self::Durable(v) => v.require_unchanged_local(local),
        }
    }
    fn import(&self, tx: &rusqlite::Transaction<'_>, account: &str) -> Result<()> {
        match self {
            Self::Legacy(v) => v.import_enabled(tx, account),
            Self::Durable(v) => v.import(tx, account),
        }
    }
}
struct WriterReconciliation {
    account: SignerAccountState,
    receipt: NativeConsentReceipt,
    active: AuthenticatedWriterSession,
    history: WriterHistory,
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
        let detail = if let WriterHistory::Durable(history) = &r.history {
            serde_json::to_string_pretty(&(
                "wholepact:signer-durable-payment-writer-reconciliation:v1",
                &r.account.account_id,
                r.account.writer_epoch,
                &r.receipt,
                r.active.disclosure(),
                r.active.snapshot(),
                r.active.receipt(),
                r.active.history_digest(),
                history,
            ))
        } else if let WriterHistory::Legacy(history) = &r.history {
            if history.has_offline() {
                serde_json::to_string_pretty(&(
                    "wholepact:signer-writer-reconciliation:v2",
                    &r.account.account_id,
                    r.account.writer_epoch,
                    &r.receipt,
                    r.active.disclosure(),
                    r.active.snapshot(),
                    r.active.receipt(),
                    r.active.history_digest(),
                    history,
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
        } else {
            return Err(JournalError::InvalidBinding);
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
    /// Complete durable-purpose history only, joined to the exact retained
    /// native-approved local intent in the SAME original-journal snapshot.
    pub(crate) fn prepare_durable_payment_writer_reconciliation_v1(
        &self,
        journal: &SignerConsentJournal,
        history: ReconciledAuthorityHistory,
        active: AuthenticatedWriterSession,
        intent: &RetainedDurablePaymentAdmissionIntentV1,
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
            let mut connection = journal
                .connection
                .lock()
                .map_err(|_| JournalError::Database)?;
            journal.database_identity.check_current(&connection)?;
            let tx = connection.transaction_with_behavior(TransactionBehavior::Deferred)?;
            journal.database_identity.check_current(&tx)?;
            let local = writer_history::WriterLocalInventory::read(
                &tx,
                &account,
                journal.capacity_limits(),
            )?;
            let prepared = writer_history::PreparedDurableWriterHistoryV1::prepare(
                &tx,
                &account,
                journal.capacity_limits(),
                &local,
                &history,
                &active,
                intent,
            )?;
            lease.check_current()?;
            if now_ms()? >= active.receipt().expires_at_ms {
                return Err(JournalError::Expired);
            }
            journal.database_identity.check_current(&tx)?;
            tx.rollback()?;
            prepared
        };
        let receipt = self.receipt()?;
        let review_digest = digest(
            "wholepact:signer-durable-payment-writer-reconciliation:v1",
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
        )?;
        let record = WriterReconciliation {
            account,
            receipt,
            active,
            history: WriterHistory::Durable(retained),
            review_digest: review_digest.clone(),
        };
        Ok(PreparedWriterReconciliation(Pending::new(
            record,
            review_digest,
            &self.inner,
        )))
    }
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
            history: WriterHistory::Legacy(retained),
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
        if !matches!(&approved.0.record.history, WriterHistory::Legacy(_)) {
            return Err(JournalError::Permission);
        }
        self.reconcile_writer_kernel(approved, None)
    }
    /// Additional deny-only source restriction for the nominal durable branch.
    /// The callback runs inside the existing fence/transaction and MUST NOT
    /// acquire a journal or session fence recursively.
    pub(crate) fn reconcile_writer_checked_v1(
        &self,
        approved: ApprovedWriterReconciliation,
        mut check_current: impl FnMut() -> Result<()>,
    ) -> Result<SignerAccountState> {
        if !matches!(&approved.0.record.history, WriterHistory::Durable(_)) {
            return Err(JournalError::Permission);
        }
        self.reconcile_writer_kernel(approved, Some(&mut check_current))
    }
    fn reconcile_writer_kernel(
        &self,
        approved: ApprovedWriterReconciliation,
        mut check_current: Option<&mut dyn FnMut() -> Result<()>>,
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
        if matches!(&r.history, WriterHistory::Durable(_)) {
            self.database_identity.check_current(&tx)?;
        }
        // Refuse before ANY mutation. This gate is also enforced by the import
        // kernel so offline plans cannot accidentally bypass it internally.
        r.history
            .require_supported(&tx, &r.account, self.capacity_limits())?;
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
        if let Some(check) = check_current.as_mut() {
            check()?;
        }
        r.history.import(&tx, &r.account.account_id)?;
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
        if matches!(&r.history, WriterHistory::Durable(_)) {
            self.database_identity.check_current(&tx)?;
        }
        if let Some(check) = check_current.as_mut() {
            check()?;
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
