//! Bounded native automation authority. Imported grant records are history only;
//! exact fresh continuations also require the private verifier and independent
//! witness admission. Grant changes never cancel retained signatures/exposure.
use super::*;
use rusqlite::{Connection, OptionalExtension, TransactionBehavior, params};
pub use wholepact_authority::{AutomationGrantBinding, AutomationGrantStatus};
use wholepact_core::automation::{AutomationAccountPolicy, AutomationGrantTerms};

/// Bound into the original exact consent digest. Absent legacy/manual values are
/// omitted from serialization, preserving every previous original reference.
#[derive(Clone, PartialEq, Eq, Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AutomationConsentBinding {
    pub grant: AutomationGrantBinding,
    pub request_digest: String,
    pub authorization_expires_at_ms: u64,
}
impl AutomationConsentBinding {
    pub(super) fn validate(&self) -> Result<()> {
        id(&self.grant.grant_id)?;
        id(&self.grant.application_id)?;
        hash(&self.grant.terms_digest)?;
        hash(&self.request_digest)?;
        if self.grant.revision == 0 || self.authorization_expires_at_ms == 0 {
            return Err(JournalError::InvalidBinding);
        }
        Ok(())
    }
}

#[derive(Clone, PartialEq, Eq, Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NativeAutomationGrantRecord {
    pub binding: AutomationGrantBinding,
    pub policy: AutomationAccountPolicy,
    pub terms: AutomationGrantTerms,
    pub enrollment_ref: String,
    pub witness: SponsorWitnessBinding,
    pub status: AutomationGrantStatus,
    pub principal_id: String,
    /// Receipt of explicit native GRANT approval. It is never a spending click.
    pub receipt: NativeConsentReceipt,
}
impl NativeAutomationGrantRecord {
    pub fn reference(&self) -> Result<String> {
        self.validate()?;
        digest("wholepact:native-automation-grant-record:v1", self)
    }
    pub(super) fn validate(&self) -> Result<()> {
        self.terms
            .validate(&self.policy)
            .map_err(|_| JournalError::InvalidBinding)?;
        self.receipt.validate()?;
        id(&self.principal_id)?;
        id(&self.witness.witness_id)?;
        hash(&self.enrollment_ref)?;
        hash(&self.witness.policy_digest)?;
        if self.binding.grant_id != self.terms.grant_id
            || self.binding.application_id != self.terms.application_id
            || self.binding.revision == 0
            || self.binding.revision > i64::MAX as u64
            || self.binding.terms_digest
                != digest(
                    "wholepact:native-automation-grant-terms:v1",
                    &(
                        &self.policy,
                        &self.terms,
                        &self.enrollment_ref,
                        &self.witness,
                    ),
                )?
            || self.receipt.writer_epoch != self.terms.writer_epoch
            || self.witness.aggregate_budget_zatoshis == 0
            || self.policy.maximum_outstanding_debit.as_zatoshis()
                > self.witness.aggregate_budget_zatoshis
        {
            return Err(JournalError::InvalidBinding);
        }
        Ok(())
    }
    pub(super) fn require_active(&self, now: u64) -> Result<()> {
        self.validate()?;
        if self.status != AutomationGrantStatus::Active {
            return Err(JournalError::Permission);
        }
        if now < self.terms.valid_from_ms
            || now >= self.terms.expires_at_ms
            || now < self.policy.valid_from_ms
            || now >= self.policy.expires_at_ms
        {
            return Err(JournalError::Expired);
        }
        Ok(())
    }
}

pub(super) fn read_current(
    c: &Connection,
    grant_id: &str,
) -> Result<Option<NativeAutomationGrantRecord>> {
    let row: Option<(u64,String,String)> = c.query_row(
        "SELECT revision,enrollment_ref,payload FROM signer_automation_grant_events WHERE grant_id=?1 ORDER BY revision DESC LIMIT 1",
        [grant_id], |r| Ok((r.get(0)?,r.get(1)?,r.get(2)?))).optional()?;
    row.map(|(revision, enrollment, raw)| {
        let record: NativeAutomationGrantRecord = decode(raw)?;
        record.validate()?;
        if record.binding.grant_id != grant_id
            || record.binding.revision != revision
            || record.enrollment_ref != enrollment
        {
            return Err(JournalError::InvalidBinding);
        }
        Ok(record)
    })
    .transpose()
}

pub(super) fn validate_transition(
    old: Option<&NativeAutomationGrantRecord>,
    next: &NativeAutomationGrantRecord,
) -> Result<()> {
    next.validate()?;
    match old {
        None if next.binding.revision == 1 && next.status == AutomationGrantStatus::Active => {
            Ok(())
        }
        Some(old)
            if old.status != AutomationGrantStatus::Revoked
                && old.binding.revision.checked_add(1) == Some(next.binding.revision)
                && old.binding.grant_id == next.binding.grant_id
                && old.binding.application_id == next.binding.application_id
                && old.enrollment_ref == next.enrollment_ref
                && old.terms.account_id == next.terms.account_id
                && old.terms.writer_epoch == next.terms.writer_epoch
                && old.principal_id == next.principal_id
                && old.witness == next.witness =>
        {
            // Pause/revoke changes only status. Updating/renewing terms is
            // an explicit new active review, never a side effect of control.
            if next.status != AutomationGrantStatus::Active
                && (old.terms != next.terms || old.policy != next.policy)
            {
                return Err(JournalError::Conflict);
            }
            Ok(())
        }
        _ => Err(JournalError::Conflict),
    }
}

pub(super) fn current_for_consent(
    c: &Connection,
    t: &SpendConsentTerms,
) -> Result<Option<NativeAutomationGrantRecord>> {
    let Some(binding) = &t.automation else {
        return Ok(None);
    };
    binding.validate()?;
    let state = storage::read_account(c)?;
    if state.recovery_required {
        return Err(JournalError::RecoveryRequired);
    }
    let grant = read_current(c, &binding.grant.grant_id)?.ok_or(JournalError::Permission)?;
    grant.require_active(now_ms()?)?;
    if grant.binding != binding.grant
        || grant.enrollment_ref != t.enrollment_ref
        || grant.terms.account_id != t.account_id
        || grant.principal_id != t.principal_id
        || grant.terms.writer_epoch != t.receipt.writer_epoch
        || grant.terms.writer_epoch != state.writer_epoch
        || binding.authorization_expires_at_ms > grant.terms.expires_at_ms
        || now_ms()? >= binding.authorization_expires_at_ms
    {
        return Err(JournalError::Permission);
    }
    Ok(Some(grant))
}

impl SignerConsentJournal {
    pub fn automation_grant(
        &self,
        grant_id: &str,
        session: &SignerConsentSession,
    ) -> Result<Option<NativeAutomationGrantRecord>> {
        id(grant_id)?;
        let account = self.account_state()?;
        let permission = session.read_lease(&self.binding(), &account)?;
        let _fence = self
            .authority_fence
            .read()
            .map_err(|_| JournalError::Permission)?;
        let c = self.connection.lock().map_err(|_| JournalError::Database)?;
        storage::check_account(&c, &account)?;
        let record = read_current(&c, grant_id)?;
        if record.as_ref().is_some_and(|g| {
            g.terms.account_id != account.account_id || g.principal_id != permission.principal
        }) {
            return Err(JournalError::Permission);
        }
        Ok(record)
    }
    /// Historical grants are deliberately returned for audit even after recovery;
    /// `eligible` is false unless enrollment/epoch and current session match.
    pub fn automation_grants(
        &self,
        session: &SignerConsentSession,
    ) -> Result<Vec<NativeAutomationGrantRecord>> {
        let account = self.account_state()?;
        let permission = session.read_lease(&self.binding(), &account)?;
        let _fence = self
            .authority_fence
            .read()
            .map_err(|_| JournalError::Permission)?;
        let c = self.connection.lock().map_err(|_| JournalError::Database)?;
        storage::check_account(&c, &account)?;
        let mut query = c.prepare("SELECT grant_id FROM signer_automation_grant_events GROUP BY grant_id ORDER BY grant_id")?;
        let ids = query
            .query_map([], |r| r.get::<_, String>(0))?
            .collect::<std::result::Result<Vec<_>, _>>()?;
        ids.into_iter()
            .map(|id| {
                let record = read_current(&c, &id)?.ok_or(JournalError::InvalidBinding)?;
                if record.terms.account_id != account.account_id
                    || record.principal_id != permission.principal
                {
                    return Err(JournalError::Permission);
                }
                Ok(record)
            })
            .collect()
    }
    pub fn record_automation_grant(
        &self,
        approved: ApprovedAutomationGrantChange,
    ) -> Result<NativeAutomationGrantRecord> {
        let approval = approved.0;
        let record = &approval.record;
        record.validate()?;
        let account = self.account_state()?;
        let permission = approval.lease(&self.binding(), &account, &record.receipt)?;
        let _fence = self
            .authority_fence
            .write()
            .map_err(|_| JournalError::Permission)?;
        let mut c = self.connection.lock().map_err(|_| JournalError::Database)?;
        let tx = c.transaction_with_behavior(TransactionBehavior::Immediate)?;
        storage::check_account(&tx, &account)?;
        let enrollment =
            storage::read_enrollment(&tx, &record.enrollment_ref)?.ok_or(JournalError::NotFound)?;
        validate_enrollment(record, &enrollment, &account, permission.principal)?;
        let old = read_current(&tx, &record.binding.grant_id)?;
        if old.as_ref() == Some(record) {
            return Ok(record.clone());
        }
        validate_transition(old.as_ref(), record)?;
        validate_account_policy(&tx, &record.policy)?;
        let raw = encode(record)?;
        tx.execute(
            "INSERT INTO signer_automation_grant_events VALUES(?1,?2,?3,?4)",
            params![
                record.binding.grant_id,
                record.binding.revision,
                record.enrollment_ref,
                raw.as_str()
            ],
        )?;
        storage::bounded(&tx, self.capacity_limits())?;
        permission.require_spending_decision(&record.receipt)?;
        tx.commit()?;
        Ok(record.clone())
    }
}

/// Account-policy identifiers are immutable across all app grants and revisions.
/// Changing an account limit or validity requires a newly reviewed policy ID;
/// the witness serializes which exact policy is currently selected.
pub(super) fn validate_account_policy(
    c: &Connection,
    policy: &AutomationAccountPolicy,
) -> Result<()> {
    let mut query = c.prepare("SELECT payload FROM signer_automation_grant_events")?;
    for raw in query.query_map([], |r| r.get::<_, String>(0))? {
        let old: NativeAutomationGrantRecord = decode(raw?)?;
        old.validate()?;
        if old.policy.policy_id == policy.policy_id && old.policy != *policy {
            return Err(JournalError::Conflict);
        }
    }
    Ok(())
}

pub(super) fn validate_enrollment(
    record: &NativeAutomationGrantRecord,
    enrollment: &AccountEnrollmentRecord,
    account: &SignerAccountState,
    principal: &str,
) -> Result<()> {
    if account.recovery_required {
        return Err(JournalError::RecoveryRequired);
    }
    let application = match enrollment.transport() {
        TransportIdentityBinding::LocalProcess {
            transport_identity_id,
            ..
        } => transport_identity_id,
        _ => return Err(JournalError::Permission),
    };
    if record.enrollment_ref != enrollment.reference()
        || record.terms.account_id != account.account_id
        || enrollment.account_id() != account.account_id
        || enrollment.principal_id() != principal
        || record.principal_id != principal
        || record.terms.writer_epoch != account.writer_epoch
        || enrollment.receipt().writer_epoch != account.writer_epoch
        || record.terms.application_id != *application
        || record.terms.agreement_ids != [enrollment.agreement_id().to_string()]
        || record.terms.network_profile != enrollment.terms.network_profile_id
        || record.policy.maximum_outstanding_debit.as_zatoshis()
            > enrollment.budget_limit_zatoshis()
        || (record.status == AutomationGrantStatus::Active
            && !storage::same_native_origin(&record.receipt, enrollment.receipt()))
    {
        return Err(JournalError::Permission);
    }
    Ok(())
}

/// Local conservative bound supplements (never replaces) the witness's shared
/// account-wide ledger. Canonical discounts are used only after the caller has
/// freshly revalidated settlement evidence in the same transaction.
pub(super) fn check_outstanding(c: &Connection, t: &SpendConsentTerms) -> Result<()> {
    let Some(binding) = &t.automation else {
        return Ok(());
    };
    let grant = current_for_consent(c, t)?.ok_or(JournalError::Permission)?;
    let mut total = u128::from(t.maximum_debit_zatoshis);
    let mut query=c.prepare("SELECT o.payload FROM signer_original_consents o JOIN signer_release_intents l ON l.authorization_id=o.authorization_id WHERE l.account_id=?1 AND (?2=0 OR NOT EXISTS(SELECT 1 FROM signer_settlement_events e WHERE e.authorization_id=l.authorization_id AND e.kind='canonical_consumed' AND e.sequence=(SELECT max(x.sequence) FROM signer_settlement_events x WHERE x.authorization_id=l.authorization_id)))")?;
    for raw in query.query_map(
        params![t.account_id, cfg!(feature = "authority-signing")],
        |r| r.get::<_, String>(0),
    )? {
        let original: OriginalSpendConsent = decode(raw?)?;
        original.validate()?;
        if original
            .terms
            .automation
            .as_ref()
            .is_some_and(|a| a.grant.grant_id == binding.grant.grant_id)
        {
            total = total
                .checked_add(u128::from(original.terms.maximum_debit_zatoshis))
                .ok_or(JournalError::BudgetExceeded)?;
        }
    }
    if total > u128::from(grant.terms.maximum_outstanding_debit.as_zatoshis()) {
        return Err(JournalError::BudgetExceeded);
    }
    Ok(())
}

#[cfg(test)]
#[path = "automation_tests.rs"]
mod tests;

/// Metadata only; signatures, wallet material and artifact bytes are excluded.
/// Settlement labels describe retained history. They do not assert that an old
/// observation is still canonical; current admission separately revalidates it.
#[derive(Clone, Serialize)]
pub struct AutomationAttemptSummary {
    pub authorization_id: String,
    pub grant: AutomationGrantBinding,
    pub original_consent_ref: String,
    pub request_digest: String,
    pub maximum_debit_zatoshis: u64,
    pub state: AutomationAttemptState,
    pub latest_settlement_record: Option<String>,
}
#[derive(Clone, Copy, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AutomationAttemptState {
    PendingWitness,
    ReservedUncertain,
    KeyUseUncertain,
    ResultRetained,
}
impl SignerConsentJournal {
    pub fn automation_attempts(
        &self,
        grant_id: Option<&str>,
        session: &SignerConsentSession,
    ) -> Result<Vec<AutomationAttemptSummary>> {
        if let Some(id_value) = grant_id {
            id(id_value)?;
        }
        let account = self.account_state()?;
        let permission = session.read_lease(&self.binding(), &account)?;
        let _fence = self
            .authority_fence
            .read()
            .map_err(|_| JournalError::Permission)?;
        let c = self.connection.lock().map_err(|_| JournalError::Database)?;
        storage::check_account(&c, &account)?;
        let mut q =
            c.prepare("SELECT authorization_id FROM signer_original_consents ORDER BY rowid")?;
        let ids = q
            .query_map([], |r| r.get::<_, String>(0))?
            .collect::<std::result::Result<Vec<_>, _>>()?;
        let mut results = Vec::new();
        for authorization in ids {
            let original =
                storage::read_original(&c, &authorization)?.ok_or(JournalError::InvalidBinding)?;
            let terms = original.original_consent().terms();
            if terms.account_id != account.account_id || terms.principal_id != permission.principal
            {
                return Err(JournalError::Permission);
            }
            let Some(automatic) = &terms.automation else {
                continue;
            };
            if grant_id.is_some_and(|id| id != automatic.grant.grant_id) {
                continue;
            }
            let (permit,keyuse,result):(bool,bool,bool)=c.query_row("SELECT EXISTS(SELECT 1 FROM signer_bridge_permits WHERE authorization_id=?1),EXISTS(SELECT 1 FROM signer_bridge_keyuse WHERE authorization_id=?1),EXISTS(SELECT 1 FROM signer_bridge_results WHERE authorization_id=?1)",[&authorization],|r|Ok((r.get(0)?,r.get(1)?,r.get(2)?)))?;
            let settlement:Option<String>=c.query_row("SELECT kind FROM signer_settlement_events WHERE authorization_id=?1 ORDER BY sequence DESC LIMIT 1",[&authorization],|r|r.get(0)).optional()?;
            results.push(AutomationAttemptSummary {
                authorization_id: authorization,
                grant: automatic.grant.clone(),
                original_consent_ref: original.original_consent().reference().into(),
                request_digest: automatic.request_digest.clone(),
                maximum_debit_zatoshis: terms.maximum_debit_zatoshis,
                state: if result {
                    AutomationAttemptState::ResultRetained
                } else if keyuse {
                    AutomationAttemptState::KeyUseUncertain
                } else if permit {
                    AutomationAttemptState::ReservedUncertain
                } else {
                    AutomationAttemptState::PendingWitness
                },
                latest_settlement_record: settlement,
            });
        }
        Ok(results)
    }
}
