//! Exact native approval of the independent signer's canonical source. Host IPC
//! cannot create this enrollment or substitute its own verified/source flags.
use super::*;
use rusqlite::{OptionalExtension, TransactionBehavior, params};
use wholepact_chain::local_node::LocalNodeSourceDescriptor;

#[derive(Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignerSettlementSource {
    reference: String,
    account_id: String,
    principal_id: String,
    source: LocalNodeSourceDescriptor,
    witness_source_digest: String,
    receipt: NativeConsentReceipt,
}
impl SignerSettlementSource {
    pub fn reference(&self) -> &str {
        &self.reference
    }
    pub fn source(&self) -> &LocalNodeSourceDescriptor {
        &self.source
    }
    pub(in crate::consent_journal) fn principal_id(&self) -> &str {
        &self.principal_id
    }
    pub fn account_id(&self) -> &str {
        &self.account_id
    }
    pub fn witness_source_digest(&self) -> &str {
        &self.witness_source_digest
    }
    /// Pure historical shape and protected-account linkage; old expiry remains
    /// readable and this cannot create a live source/session capability.
    pub(in crate::consent_journal) fn validate_history(
        &self,
        account: &SignerAccountState,
    ) -> Result<()> {
        self.validate()?;
        self.receipt.validate()?;
        if self.account_id != account.account_id
            || self.receipt.writer_epoch() > account.writer_epoch
        {
            return Err(JournalError::InvalidBinding);
        }
        Ok(())
    }
    pub(in crate::consent_journal) fn validate(&self) -> Result<()> {
        self.source
            .validate()
            .map_err(|_| JournalError::InvalidBinding)?;
        id(&self.account_id)?;
        id(&self.principal_id)?;
        hash(&self.witness_source_digest)?;
        if self.reference
            != digest(
                "wholepact:signer-settlement-source:v1",
                &(
                    &self.account_id,
                    &self.principal_id,
                    &self.source,
                    &self.witness_source_digest,
                    &self.receipt,
                ),
            )?
        {
            return Err(JournalError::InvalidBinding);
        }
        Ok(())
    }
}
pub struct PreparedSettlementSource(Pending<SignerSettlementSource>);
pub struct ApprovedSettlementSource(Approval<SignerSettlementSource>);
impl PreparedSettlementSource {
    pub fn review_digest(&self) -> &str {
        &self.0.review_digest
    }
    pub fn display(&self) -> Result<String> {
        let _lease = self.0.session.read()?;
        let r = &self.0.record;
        Ok(format!(
            "ENROLL INDEPENDENT SIGNER SETTLEMENT SOURCE\nAccount: {}\nExact endpoint, TLS identities, node release, network and confirmation policy:\n{}\nIndependent witness source digest: {}\nThis named owner-controlled node and TLS terminator are trusted to report fresh canonical state. Reads disclose exact transaction linkage. Only canonical consumption of this signer's exact original inputs can resolve exposure. Reorganizations reopen exposure and fence further authorization. No expiry, missing report or saved verified flag clears exposure. This does not enroll the independent witness source, grant new spending authority, or deploy a node.\nExact review: {}",
            r.account_id,
            serde_json::to_string_pretty(&r.source).map_err(|_| JournalError::InvalidBinding)?,
            r.witness_source_digest,
            self.review_digest()
        ))
    }
}
impl SignerConsentSession {
    pub fn prepare_settlement_source(
        &self,
        journal: &SignerConsentJournal,
        source: LocalNodeSourceDescriptor,
        witness_source_digest: String,
    ) -> Result<PreparedSettlementSource> {
        let account = journal.account_state()?;
        let lease = self.read_lease(&journal.binding(), &account)?;
        if account.recovery_required {
            return Err(JournalError::RecoveryRequired);
        }
        hash(&witness_source_digest)?;
        let receipt = self.receipt()?;
        let reference = digest(
            "wholepact:signer-settlement-source:v1",
            &(
                &account.account_id,
                lease.principal,
                &source,
                &witness_source_digest,
                &receipt,
            ),
        )?;
        let record = SignerSettlementSource {
            reference: reference.clone(),
            account_id: account.account_id,
            principal_id: lease.principal.into(),
            source,
            witness_source_digest,
            receipt,
        };
        record.validate()?;
        Ok(PreparedSettlementSource(Pending::new(
            record,
            reference,
            &self.inner,
        )))
    }
    pub fn approve_settlement_source(
        &self,
        prepared: PreparedSettlementSource,
        decision: NativeConsentDecision,
    ) -> Result<ApprovedSettlementSource> {
        Ok(ApprovedSettlementSource(
            prepared.0.approve(self, decision)?,
        ))
    }
}
impl SignerConsentJournal {
    pub fn record_settlement_source(
        &self,
        approved: ApprovedSettlementSource,
    ) -> Result<SignerSettlementSource> {
        let a = approved.0;
        let r = &a.record;
        r.validate()?;
        let account = self.account_state()?;
        let permission = a.lease(&self.binding(), &account, &r.receipt)?;
        let _fence = self
            .authority_fence
            .write()
            .map_err(|_| JournalError::Permission)?;
        let mut c = self.connection.lock().map_err(|_| JournalError::Database)?;
        let tx = c.transaction_with_behavior(TransactionBehavior::Immediate)?;
        storage::check_account(&tx, &account)?;
        if account.account_id != r.account_id || permission.principal != r.principal_id {
            return Err(JournalError::Permission);
        }
        let mut existing =
            tx.prepare("SELECT payload FROM signer_settlement_sources WHERE account_id=?1")?;
        for payload in existing.query_map([&r.account_id], |row| row.get::<_, String>(0))? {
            let prior: SignerSettlementSource = decode(payload?)?;
            prior.validate()?;
            if prior.source != r.source || prior.witness_source_digest != r.witness_source_digest {
                return Err(JournalError::Conflict);
            }
        }
        drop(existing);
        let raw = encode(r)?;
        let old: Option<String> = tx
            .query_row(
                "SELECT payload FROM signer_settlement_sources WHERE reference=?1",
                [&r.reference],
                |row| row.get(0),
            )
            .optional()?;
        if let Some(old) = old {
            if old != *raw {
                return Err(JournalError::Conflict);
            }
        } else {
            tx.execute("INSERT INTO signer_settlement_sources(reference,account_id,payload) VALUES(?1,?2,?3)",params![r.reference,r.account_id,raw.as_str()])?;
        }
        storage::bounded(&tx, self.capacity_limits())?;
        permission.check_current()?;
        tx.commit()?;
        Ok(r.clone())
    }
    pub fn settlement_source(
        &self,
        reference: &str,
        session: &SignerConsentSession,
    ) -> Result<SignerSettlementSource> {
        hash(reference)?;
        let account = self.account_state()?;
        let permission = session.read_lease(&self.binding(), &account)?;
        let c = self.connection.lock().map_err(|_| JournalError::Database)?;
        let raw: String = c.query_row("SELECT payload FROM signer_settlement_sources WHERE reference=?1 AND account_id=?2",params![reference,account.account_id],|r|r.get(0)).optional()?.ok_or(JournalError::NotFound)?;
        let record: SignerSettlementSource = decode(raw)?;
        record.validate()?;
        if record.reference != reference
            || record.account_id != account.account_id
            || record.principal_id != permission.principal
        {
            return Err(JournalError::Permission);
        }
        permission.check_current()?;
        Ok(record)
    }
}
