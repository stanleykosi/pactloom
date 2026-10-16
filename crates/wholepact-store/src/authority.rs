//! Signer authority ledger. No key handling or transaction verification.
//! Integration must remain unavailable until trusted verification, encrypted
//! storage and writer/restore reconciliation have been qualified.

use crate::{Result, Store, StoreError, encode, now_ms, request_digest, validate_id};
use rusqlite::{OptionalExtension, TransactionBehavior, params};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ExposureState {
    AuthorizedLocally,
    Released,
    OutstandingUncertain,
    ExpiredObserved,
    ConflictedObserved,
    Consumed,
}
impl ExposureState {
    /// Current lifecycle transition class, not budget or input eligibility.
    pub fn is_outstanding(self) -> bool {
        matches!(
            self,
            Self::AuthorizedLocally | Self::Released | Self::OutstandingUncertain
        )
    }
    /// A branch-local conflict/expiry observation retains the original charge.
    /// Consumed debit remains charged separately against the lifetime budget.
    pub fn retains_unresolved_exposure(self) -> bool {
        self != Self::Consumed
    }
    fn as_str(self) -> &'static str {
        match self {
            Self::AuthorizedLocally => "authorized_locally",
            Self::Released => "released",
            Self::OutstandingUncertain => "outstanding_uncertain",
            Self::ExpiredObserved => "expired_observed",
            Self::ConflictedObserved => "conflicted_observed",
            Self::Consumed => "consumed",
        }
    }
    fn parse(value: &str) -> Result<Self> {
        match value {
            "authorized_locally" => Ok(Self::AuthorizedLocally),
            "released" => Ok(Self::Released),
            "outstanding_uncertain" => Ok(Self::OutstandingUncertain),
            "expired_observed" => Ok(Self::ExpiredObserved),
            "conflicted_observed" => Ok(Self::ConflictedObserved),
            "consumed" => Ok(Self::Consumed),
            _ => Err(StoreError::InvalidInput("unknown exposure state")),
        }
    }
}

/// Already-verified request submitted by the signer, not a public API DTO.
/// This record contains sensitive correlation information. The current metadata
/// store must be encrypted before real protected material is retained.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReleaseIntent {
    pub authorization_id: String,
    pub account_id: String,
    pub writer_epoch: u64,
    pub obligation_id: String,
    pub proposal_id: String,
    pub manifest_digest: String,
    pub effects_digest: String,
    pub artifact_digest: String,
    pub maximum_debit: String,
    pub input_ids: Vec<String>,
    /// Authoritative effective bound derived from the signer's current grant.
    /// A client must never select this value itself.
    pub aggregate_budget_limit: String,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StoredExposure {
    pub intent: ReleaseIntent,
    pub state: ExposureState,
    pub release_intent_recorded: bool,
    pub created_at_ms: i64,
    pub updated_at_ms: i64,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuthorityAccount {
    pub account_id: String,
    pub writer_epoch: u64,
    pub recovery_required: bool,
}

impl Store {
    /// Bootstrap only for a new isolated account. Restores must use
    /// `import_restored_account`, which can never restore signing readiness.
    pub fn initialize_authority_account(&self, account_id: &str, writer_epoch: u64) -> Result<()> {
        self.insert_authority_account(account_id, writer_epoch, false)
    }
    pub fn import_restored_account(&self, account_id: &str, writer_epoch: u64) -> Result<()> {
        self.insert_authority_account(account_id, writer_epoch, true)
    }
    fn insert_authority_account(
        &self,
        account_id: &str,
        writer_epoch: u64,
        recovery_required: bool,
    ) -> Result<()> {
        validate_id(account_id)?;
        let epoch = i64::try_from(writer_epoch)
            .map_err(|_| StoreError::InvalidInput("writer epoch overflow"))?;
        let c = self.connection.lock().map_err(|_| StoreError::Poisoned)?;
        if !recovery_required && crate::backup::read_recovery_state(&c)?.recovery_required {
            return Err(StoreError::RecoveryRequired);
        }
        let exists: bool = c.query_row(
            "SELECT EXISTS(SELECT 1 FROM authority_accounts WHERE account_id=?1)",
            [account_id],
            |r| r.get(0),
        )?;
        if exists {
            return Err(StoreError::AlreadyExists);
        }
        c.execute("INSERT INTO authority_accounts(account_id,writer_epoch,recovery_required) VALUES(?1,?2,?3)",params![account_id,epoch,recovery_required])?;
        Ok(())
    }
    pub fn authority_account(&self, account_id: &str) -> Result<Option<AuthorityAccount>> {
        let c = self.connection.lock().map_err(|_| StoreError::Poisoned)?;
        Ok(c.query_row("SELECT account_id,writer_epoch,recovery_required FROM authority_accounts WHERE account_id=?1",[account_id],|r|Ok(AuthorityAccount{account_id:r.get(0)?,writer_epoch:r.get::<_,i64>(1)? as u64,recovery_required:r.get(2)?})).optional()?)
    }
    /// Conservative one-way operation. Clearing recovery requires a separately
    /// qualified reconciliation protocol; no convenience clear flag is exposed.
    pub fn require_account_recovery(&self, account_id: &str) -> Result<()> {
        let c = self.connection.lock().map_err(|_| StoreError::Poisoned)?;
        if c.execute(
            "UPDATE authority_accounts SET recovery_required=1 WHERE account_id=?1",
            [account_id],
        )? == 0
        {
            return Err(StoreError::NotFound);
        }
        Ok(())
    }
    /// Atomic reserve + release intent. Success means a usable authorization may
    /// subsequently be exported; a crash after this call leaves full exposure.
    /// No cryptographic authorization is produced here.
    pub fn record_authorization_release_intent(
        &self,
        intent: &ReleaseIntent,
    ) -> Result<StoredExposure> {
        let mut c = self.connection.lock().map_err(|_| StoreError::Poisoned)?;
        let tx = c.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let exposure = record_release_intent_in_transaction(&tx, intent, now_ms())?;
        tx.commit()?;
        Ok(exposure)
    }
    pub fn exposure(&self, authorization_id: &str) -> Result<Option<StoredExposure>> {
        let c = self.connection.lock().map_err(|_| StoreError::Poisoned)?;
        read_exposure(&c, authorization_id)
    }
    pub fn account_exposures(&self, account_id: &str) -> Result<Vec<StoredExposure>> {
        let c = self.connection.lock().map_err(|_| StoreError::Poisoned)?;
        let mut q=c.prepare("SELECT authorization_id FROM authority_exposures WHERE account_id=?1 ORDER BY created_at_ms,authorization_id")?;
        let ids = q
            .query_map([account_id], |r| r.get::<_, String>(0))?
            .collect::<std::result::Result<Vec<_>, _>>()?;
        ids.iter()
            .map(|id| read_exposure(&c, id)?.ok_or(StoreError::NotFound))
            .collect()
    }
    pub fn outstanding_debit(&self, account_id: &str) -> Result<String> {
        let mut total: u128 = 0;
        for item in self.account_exposures(account_id)? {
            if item.state.retains_unresolved_exposure() {
                total = total
                    .checked_add(amount(&item.intent.maximum_debit)? as u128)
                    .ok_or(StoreError::BudgetExceeded)?;
            }
        }
        Ok(total.to_string())
    }
    /// Settled debits remain charged against a reusable aggregate budget. A
    /// reorganization moves them back to outstanding, never counting both.
    pub fn settled_debit(&self, account_id: &str) -> Result<String> {
        let mut total: u128 = 0;
        for item in self.account_exposures(account_id)? {
            if item.state == ExposureState::Consumed {
                total = total
                    .checked_add(amount(&item.intent.maximum_debit)? as u128)
                    .ok_or(StoreError::BudgetExceeded)?;
            }
        }
        Ok(total.to_string())
    }
    pub fn mark_authorization_released(&self, authorization_id: &str) -> Result<()> {
        let mut c = self.connection.lock().map_err(|_| StoreError::Poisoned)?;
        let tx = c.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let old = read_exposure(&tx, authorization_id)?.ok_or(StoreError::NotFound)?;
        if self.generation_fenced(&tx, "obligation", &old.intent.obligation_id)? {
            return Err(StoreError::RecoveryRequired);
        }
        if old.state == ExposureState::Released {
            return Ok(());
        }
        if !old.state.is_outstanding() {
            return Err(StoreError::InvalidTransition);
        }
        tx.execute("UPDATE authority_exposures SET state='released',updated_at_ms=?2 WHERE authorization_id=?1",params![authorization_id,now_ms()])?;
        tx.execute("INSERT INTO authority_events(authorization_id,kind,occurred_at_ms) VALUES(?1,'authorization_released',?2)",params![authorization_id,now_ms()])?;
        tx.commit()?;
        Ok(())
    }
    /// Records already-validated chain evidence. The caller must enforce the
    /// qualified expiry/conflict/confirmation policy; an arbitrary external
    /// assertion may never reach this method. All records remain retained.
    /// Conflict/expiry labels preserve reservations, debit and obligation fences;
    /// they are not replacement or reclaim authority. Historical missing
    /// reservations remain covered by retained-payload checks on admission.
    pub fn record_observed_resolution(
        &self,
        authorization_id: &str,
        state: ExposureState,
        evidence_ref: &str,
    ) -> Result<()> {
        if state.is_outstanding() {
            return Err(StoreError::InvalidTransition);
        }
        validate_id(evidence_ref)?;
        let mut c = self.connection.lock().map_err(|_| StoreError::Poisoned)?;
        let tx = c.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let old = read_exposure(&tx, authorization_id)?.ok_or(StoreError::NotFound)?;
        if self.generation_fenced(&tx, "obligation", &old.intent.obligation_id)? {
            return Err(StoreError::RecoveryRequired);
        }
        if old.state == state {
            return Ok(());
        }
        if !old.state.is_outstanding() {
            return Err(StoreError::InvalidTransition);
        }
        tx.execute(
            "UPDATE authority_exposures SET state=?2,updated_at_ms=?3 WHERE authorization_id=?1",
            params![authorization_id, state.as_str(), now_ms()],
        )?;
        if state == ExposureState::Consumed {
            tx.execute(
                "DELETE FROM authority_reservations WHERE authorization_id=?1",
                [authorization_id],
            )?;
        }
        tx.execute("INSERT INTO authority_events(authorization_id,kind,evidence_ref,occurred_at_ms) VALUES(?1,?2,?3,?4)",params![authorization_id,state.as_str(),evidence_ref,now_ms()])?;
        tx.commit()?;
        Ok(())
    }
    /// A reorganization can revive prior signatures. Reopen full exposure and
    /// quarantine the account; any replacement reservations remain visible.
    pub fn reopen_exposure_after_reorg(
        &self,
        authorization_id: &str,
        evidence_ref: &str,
    ) -> Result<()> {
        validate_id(evidence_ref)?;
        let mut c = self.connection.lock().map_err(|_| StoreError::Poisoned)?;
        let tx = c.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let old = read_exposure(&tx, authorization_id)?.ok_or(StoreError::NotFound)?;
        if self.generation_fenced(&tx, "obligation", &old.intent.obligation_id)? {
            return Err(StoreError::RecoveryRequired);
        }
        tx.execute("UPDATE authority_exposures SET state='outstanding_uncertain',updated_at_ms=?2 WHERE authorization_id=?1",params![authorization_id,now_ms()])?;
        tx.execute(
            "UPDATE authority_accounts SET recovery_required=1 WHERE account_id=?1",
            [&old.intent.account_id],
        )?;
        for input in &old.intent.input_ids {
            // A replacement may reserve a common input. Retain both exposure
            // records and force reconciliation rather than overwrite a claim.
            tx.execute("INSERT OR IGNORE INTO authority_reservations(account_id,input_id,authorization_id) VALUES(?1,?2,?3)",params![old.intent.account_id,input,authorization_id])?;
        }
        tx.execute("INSERT INTO authority_events(authorization_id,kind,evidence_ref,occurred_at_ms) VALUES(?1,'reorg_exposure_reopened',?2,?3)",params![authorization_id,evidence_ref,now_ms()])?;
        tx.commit()?;
        Ok(())
    }
}
fn read_exposure(c: &rusqlite::Connection, id: &str) -> Result<Option<StoredExposure>> {
    let raw=c.query_row("SELECT payload,state,release_intent,created_at_ms,updated_at_ms FROM authority_exposures WHERE authorization_id=?1",[id],|r|Ok((r.get::<_,String>(0)?,r.get::<_,String>(1)?,r.get::<_,bool>(2)?,r.get::<_,i64>(3)?,r.get::<_,i64>(4)?))).optional()?;
    raw.map(
        |(payload, state, release_intent_recorded, created_at_ms, updated_at_ms)| {
            Ok(StoredExposure {
                intent: serde_json::from_str(&payload)?,
                state: ExposureState::parse(&state)?,
                release_intent_recorded,
                created_at_ms,
                updated_at_ms,
            })
        },
    )
    .transpose()
}
fn amount(value: &str) -> Result<u64> {
    if value.is_empty()
        || (value.len() > 1 && value.starts_with('0'))
        || !value.bytes().all(|b| b.is_ascii_digit())
    {
        return Err(StoreError::InvalidInput(
            "amount must be canonical nonnegative integer string",
        ));
    }
    value
        .parse::<u64>()
        .map_err(|_| StoreError::InvalidInput("amount overflow"))
}
pub(crate) fn validate_intent(intent: &ReleaseIntent) -> Result<()> {
    for id in [
        &intent.authorization_id,
        &intent.account_id,
        &intent.obligation_id,
        &intent.proposal_id,
    ] {
        validate_id(id)?;
    }
    for digest in [
        &intent.manifest_digest,
        &intent.effects_digest,
        &intent.artifact_digest,
    ] {
        if digest.len() != 64
            || !digest
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        {
            return Err(StoreError::InvalidInput("invalid authorization digest"));
        }
    }
    amount(&intent.maximum_debit)?;
    amount(&intent.aggregate_budget_limit)?;
    if intent.input_ids.is_empty() || intent.input_ids.len() > 1024 {
        return Err(StoreError::InvalidInput("input count must be 1 to 1024"));
    }
    let mut unique = BTreeSet::new();
    for input in &intent.input_ids {
        validate_id(input)?;
        if !unique.insert(input) {
            return Err(StoreError::InvalidInput("duplicate input"));
        }
    }
    Ok(())
}

/// Shared atomic ledger implementation. The caller owns the IMMEDIATE
/// transaction so grant checks, reservations and audit either all commit or none
/// do. Only the automation orchestrator uses this alongside the public wrapper.
pub(crate) fn record_release_intent_in_transaction(
    tx: &rusqlite::Transaction<'_>,
    intent: &ReleaseIntent,
    now: i64,
) -> Result<StoredExposure> {
    validate_intent(intent)?;
    let maximum = amount(&intent.maximum_debit)?;
    let budget = amount(&intent.aggregate_budget_limit)?;
    let value = serde_json::to_value(intent)?;
    let digest = request_digest(&value)?;
    let encoded = encode(&value)?;
    if let Some(old) = read_exposure(tx, &intent.authorization_id)? {
        // Replay never produces new authority, even if the account has
        // entered recovery since the original durable intent.
        if old.intent != *intent {
            return Err(StoreError::IdempotencyConflict);
        }
        return Ok(old);
    }
    // A prior source-bound loss applies to future local alternatives too. New
    // accounts cannot evade an obligation fence by having no earlier exposure.
    let obligation_fenced: bool = tx.query_row("SELECT EXISTS(SELECT 1 FROM records WHERE aggregate_type='settlement_applied' AND payload=?1)", [encode(&serde_json::json!(&intent.obligation_id))?], |r|r.get(0))?;
    if obligation_fenced {
        return Err(StoreError::RecoveryRequired);
    }
    let budget = crate::automation::account_budget_ceiling(tx, &intent.account_id)?
        .map_or(budget, |ceiling| budget.min(ceiling));
    if crate::backup::read_recovery_state(tx)?.recovery_required {
        return Err(StoreError::RecoveryRequired);
    }
    let account = tx
        .query_row(
            "SELECT writer_epoch,recovery_required FROM authority_accounts WHERE account_id=?1",
            [&intent.account_id],
            |r| Ok((r.get::<_, i64>(0)?, r.get::<_, bool>(1)?)),
        )
        .optional()?
        .ok_or(StoreError::NotFound)?;
    if account.1 {
        return Err(StoreError::RecoveryRequired);
    }
    if account.0 as u64 != intent.writer_epoch {
        return Err(StoreError::WriterEpochMismatch);
    }
    let existing: bool = tx.query_row(
        "SELECT EXISTS(SELECT 1 FROM authority_exposures WHERE account_id=?1 AND obligation_id=?2)",
        params![intent.account_id, intent.obligation_id],
        |r| r.get(0),
    )?;
    if existing {
        return Err(StoreError::LiveAuthorizationExists);
    }
    // Every retained release counts against lifetime allowance, regardless of
    // its last chain label. The payloads also preserve input claims from legacy
    // journals whose old resolution writer removed their reservation rows.
    let mut total: u128 = 0;
    let candidate_inputs: BTreeSet<_> = intent.input_ids.iter().collect();
    let mut retained_input_conflict = false;
    {
        let mut q = tx.prepare("SELECT authorization_id,maximum_debit,payload FROM authority_exposures WHERE account_id=?1")?;
        let rows = q.query_map([&intent.account_id], |r| {
            Ok((
                r.get::<_, String>(0)?,
                r.get::<_, String>(1)?,
                r.get::<_, String>(2)?,
            ))
        })?;
        for row in rows {
            let (authorization_id, maximum_debit, payload) = row?;
            let original: ReleaseIntent = serde_json::from_str(&payload)?;
            validate_intent(&original)?;
            if original.account_id != intent.account_id
                || original.authorization_id != authorization_id
                || original.maximum_debit != maximum_debit
            {
                return Err(StoreError::RecoveryRequired);
            }
            total = total
                .checked_add(amount(&maximum_debit)? as u128)
                .ok_or(StoreError::BudgetExceeded)?;
            retained_input_conflict |= original
                .input_ids
                .iter()
                .any(|input| candidate_inputs.contains(input));
        }
    }
    if total
        .checked_add(maximum as u128)
        .ok_or(StoreError::BudgetExceeded)?
        > budget as u128
    {
        return Err(StoreError::BudgetExceeded);
    }
    if retained_input_conflict {
        return Err(StoreError::InputReserved);
    }
    for input in &intent.input_ids {
        let reserved:bool=tx.query_row("SELECT EXISTS(SELECT 1 FROM authority_reservations WHERE account_id=?1 AND input_id=?2)",params![intent.account_id,input],|r|r.get(0))?;
        if reserved {
            return Err(StoreError::InputReserved);
        }
    }
    tx.execute("INSERT INTO authority_exposures(authorization_id,account_id,obligation_id,proposal_id,request_digest,maximum_debit,state,release_intent,payload,created_at_ms,updated_at_ms) VALUES(?1,?2,?3,?4,?5,?6,'outstanding_uncertain',1,?7,?8,?8)",params![intent.authorization_id,intent.account_id,intent.obligation_id,intent.proposal_id,digest,intent.maximum_debit,encoded,now])?;
    for input in &intent.input_ids {
        tx.execute("INSERT INTO authority_reservations(account_id,input_id,authorization_id) VALUES(?1,?2,?3)",params![intent.account_id,input,intent.authorization_id])?;
    }
    tx.execute("INSERT INTO authority_events(authorization_id,kind,occurred_at_ms) VALUES(?1,'release_intent_recorded',?2)",params![intent.authorization_id,now])?;
    Ok(StoredExposure {
        intent: intent.clone(),
        state: ExposureState::OutstandingUncertain,
        release_intent_recorded: true,
        created_at_ms: now,
        updated_at_ms: now,
    })
}
