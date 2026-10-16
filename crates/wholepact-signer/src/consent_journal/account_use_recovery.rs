//! Monotone historical retention, never fresh account admission.
use super::*;
use rusqlite::{Connection, Transaction, params_from_iter, types::Value};
use wholepact_authority::{
    ReconciledAuthorityHistory,
    account_use::{AccountUseGenesis, PermanentAccountExclusion},
    account_use_link::{ReconciledAccountExclusion, reconcile_account_exclusion_complete},
};
use wholepact_storage_security::bundle::recovery::{RecoveryCell, VerifiedSignerRecoverySource};

pub(super) struct RecoveryAccountUseRetention {
    genesis: Option<AccountUseGenesis>,
    exclusion: Option<PermanentAccountExclusion>,
    acknowledgement: Option<ReconciledAccountExclusion>,
}
impl RecoveryAccountUseRetention {
    pub(super) fn genesis(&self) -> Option<&AccountUseGenesis> {
        self.genesis.as_ref()
    }
    pub(super) fn exclusion(&self) -> Option<&PermanentAccountExclusion> {
        self.exclusion.as_ref()
    }
    pub(super) fn acknowledgement(
        &self,
    ) -> Option<&wholepact_authority::account_use_link::AccountExclusionReceipt> {
        self.acknowledgement.as_ref().map(|a| a.evidence())
    }

    pub(super) fn digest(&self) -> Result<Option<String>> {
        if self.genesis.is_none() {
            return Ok(None);
        }
        digest(
            "wholepact:signer-account-use-recovery-retention:v1",
            &(
                &self.genesis,
                &self.exclusion,
                self.acknowledgement.as_ref().map(|a| a.evidence()),
            ),
        )
        .map(Some)
    }
    pub(super) fn display(&self) -> Result<String> {
        serde_json::to_string_pretty(&(
            &self.genesis,
            &self.exclusion,
            self.acknowledgement.as_ref().map(|a| a.evidence()),
        ))
        .map_err(|_| JournalError::InvalidBinding)
    }
    pub(super) fn retain_on(&self, tx: &Transaction<'_>, account: &str) -> Result<()> {
        let existing = account_use_storage::inspect(tx, account)?;
        if existing.genesis() != self.genesis.as_ref()
            || existing
                .exclusion()
                .is_some_and(|e| Some(e) != self.exclusion.as_ref())
        {
            return Err(JournalError::Conflict);
        }
        if let Some(e) = &self.exclusion {
            account_use_storage::append_exclusion(tx, account, e)?;
        }
        if let Some(ack) = &self.acknowledgement {
            account_use_storage::append_witness_ack(tx, account, ack)?;
        }
        // A missing source genesis is never filled from a newer witness claim.
        // No budget, epoch, quarantine, grant, permit or original consent changes.
        Ok(())
    }
}

pub(super) fn reconcile(
    source: &VerifiedSignerRecoverySource,
    history: &ReconciledAuthorityHistory,
) -> Result<RecoveryAccountUseRetention> {
    history
        .require_legacy_online_only()
        .map_err(|_| JournalError::OfflineHistoryUnsupported)?;
    reconcile_complete(source, history)
}

/// Complete historical provenance validation; it grants no activation or fresh
/// account use. Callers retain their independent native/recovery support gates.
pub(super) fn reconcile_complete(
    source: &VerifiedSignerRecoverySource,
    history: &ReconciledAuthorityHistory,
) -> Result<RecoveryAccountUseRetention> {
    let account = &history.snapshot().account_id;
    let account_table = source.account().map_err(|_| JournalError::InvalidBinding)?;
    let account_column = account_table
        .columns()
        .iter()
        .position(|v| v == "account_id")
        .ok_or(JournalError::InvalidBinding)?;
    if account_table.rows().len() != 1
        || !matches!(account_table.rows()[0].cells().get(account_column), Some(RecoveryCell::Text(v)) if v == account)
    {
        return Err(JournalError::InvalidBinding);
    }
    if !(8..=15).contains(&source.provenance().schema_version) {
        return Err(JournalError::UnsupportedSchema);
    }
    if source
        .tables()
        .iter()
        .any(|t| t.name() == "signer_common_context_reentry_v1" && !t.rows().is_empty())
    {
        return Err(JournalError::ConstructionHistoryUnsupported);
    }
    let mut c = Connection::open_in_memory()?;
    c.execute_batch("PRAGMA foreign_keys=ON;")?;
    let tx = c.transaction()?;
    tx.execute_batch(recovery_migration::ACCOUNT_USE_SCHEMA)?;
    tx.execute_batch("PRAGMA defer_foreign_keys=ON;")?;
    let names = [
        "signer_account_use_genesis",
        "signer_account_use_exclusion",
        "signer_account_use_witness_ack",
    ];
    for name in names {
        let table = source.tables().iter().find(|t| t.name() == name);
        if source.provenance().schema_version < 12 {
            if table.is_some() {
                return Err(JournalError::InvalidBinding);
            }
            continue;
        }
        let table = table.ok_or(JournalError::InvalidBinding)?;
        // Source table names/columns are sealed against the executable-owned
        // exact version template; no caller-provided SQL identifier enters here.
        let columns = table
            .columns()
            .iter()
            .map(|s| format!("\"{}\"", s.replace('"', "\"\"")))
            .collect::<Vec<_>>();
        let sql = format!(
            "INSERT INTO {name}({}) VALUES({})",
            columns.join(","),
            vec!["?"; columns.len()].join(",")
        );
        for row in table.rows() {
            let values = row
                .cells()
                .iter()
                .map(|cell| match cell {
                    RecoveryCell::Null => Ok(Value::Null),
                    RecoveryCell::Integer(v) => Ok(Value::Integer(*v)),
                    RecoveryCell::Text(v) => Ok(Value::Text(v.clone())),
                    _ => Err(JournalError::InvalidBinding),
                })
                .collect::<Result<Vec<_>>>()?;
            tx.execute(&sql, params_from_iter(values))?;
        }
    }
    let source_state = account_use_storage::inspect(&tx, account)?;
    reconcile_stored(&source_state, history)
}

/// Same projection checks for the live complete read transaction. This is
/// historical consistency only and does not write newer witness exclusions.
pub(super) fn reconcile_live(
    c: &Connection,
    history: &ReconciledAuthorityHistory,
) -> Result<RecoveryAccountUseRetention> {
    if c.is_autocommit() {
        return Err(JournalError::InvalidBinding);
    }
    let state = account_use_storage::inspect(c, &history.snapshot().account_id)?;
    reconcile_stored(&state, history)
}
fn reconcile_stored(
    source_state: &account_use_storage::StoredAccountUse,
    history: &ReconciledAuthorityHistory,
) -> Result<RecoveryAccountUseRetention> {
    let projection = history.account_use_history();
    validate_projection_pair(
        source_state.genesis(),
        source_state.exclusion(),
        projection.genesis(),
        projection.exclusion(),
    )?;
    match (source_state.genesis(), projection.genesis()) {
        (None, None) => {
            if source_state.exclusion().is_some()
                || source_state.witness_ack().is_some()
                || projection.exclusion().is_some()
            {
                return Err(JournalError::InvalidBinding);
            }
            Ok(RecoveryAccountUseRetention {
                genesis: None,
                exclusion: None,
                acknowledgement: None,
            })
        }
        (Some(g), Some(current)) if g == current => {
            if source_state
                .exclusion()
                .is_some_and(|e| Some(e) != projection.exclusion())
            {
                return Err(JournalError::Conflict);
            }
            let acknowledgement = projection
                .exclusion()
                .map(|e| {
                    reconcile_account_exclusion_complete(history, g, history.disclosure(), e)
                        .map_err(|_| JournalError::InvalidBinding)
                })
                .transpose()?;
            if source_state
                .witness_ack()
                .is_some_and(|old| acknowledgement.as_ref().is_none_or(|a| a.evidence() != old))
            {
                return Err(JournalError::Conflict);
            }
            Ok(RecoveryAccountUseRetention {
                genesis: Some(g.clone()),
                exclusion: projection.exclusion().cloned(),
                acknowledgement,
            })
        }
        // Legacy unknown cannot acquire retrospective genesis; missing surviving
        // birth history cannot erase retained origin or a post-backup exclusion.
        _ => Err(JournalError::RecoveryRequired),
    }
}

/// Pure historical consistency predicate only. Raw records cannot issue a
/// native approval, witness acknowledgement or fresh-use capability.
fn validate_projection_pair(
    source_genesis: Option<&AccountUseGenesis>,
    source_exclusion: Option<&PermanentAccountExclusion>,
    current_genesis: Option<&AccountUseGenesis>,
    current_exclusion: Option<&PermanentAccountExclusion>,
) -> Result<()> {
    match (source_genesis, current_genesis) {
        (None, None) if source_exclusion.is_none() && current_exclusion.is_none() => Ok(()),
        (Some(a), Some(b)) if a == b => {
            a.validate().map_err(|_| JournalError::InvalidBinding)?;
            for event in [source_exclusion, current_exclusion].into_iter().flatten() {
                event.validate().map_err(|_| JournalError::InvalidBinding)?;
                if event.identity != a.identity
                    || event.genesis_digest
                        != a.digest().map_err(|_| JournalError::InvalidBinding)?
                {
                    return Err(JournalError::InvalidBinding);
                }
            }
            if source_exclusion.is_some_and(|e| Some(e) != current_exclusion) {
                return Err(JournalError::Conflict);
            }
            Ok(())
        }
        _ => Err(JournalError::RecoveryRequired),
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    use wholepact_authority::account_use::{AccountUseIdentity, ExclusionReason};
    fn g() -> AccountUseGenesis {
        AccountUseGenesis {
            version: 1,
            identity: AccountUseIdentity {
                account_id: "11".repeat(32),
                full_viewing_key_digest: "22".repeat(32),
                network_profile_id: "synthetic".into(),
                derivation_domain: "dedicated-testnet-legacy-zip32-v1".into(),
            },
            witness_id: "witness".into(),
            witness_origin_digest: "33".repeat(32),
            owner_certificate_digest: "44".repeat(32),
            native_birth_digest: "55".repeat(32),
        }
    }
    #[test]
    fn absent_legacy_is_unknown_and_cannot_gain_retrospective_genesis() {
        let genesis = g();
        assert!(validate_projection_pair(None, None, None, None).is_ok());
        assert!(validate_projection_pair(None, None, Some(&genesis), None).is_err());
        assert!(validate_projection_pair(Some(&genesis), None, None, None).is_err());
    }
    #[test]
    fn current_exclusion_is_retained_and_source_exclusion_cannot_disappear() {
        let genesis = g();
        let e = PermanentAccountExclusion {
            version: 1,
            identity: genesis.identity.clone(),
            genesis_digest: genesis.digest().unwrap(),
            operation_id: "retire".into(),
            native_review_digest: "66".repeat(32),
            reason: ExclusionReason::RetirementRequested,
        };
        assert!(validate_projection_pair(Some(&genesis), None, Some(&genesis), Some(&e)).is_ok());
        assert!(
            validate_projection_pair(Some(&genesis), Some(&e), Some(&genesis), Some(&e)).is_ok()
        );
        assert!(validate_projection_pair(Some(&genesis), Some(&e), Some(&genesis), None).is_err());
        let mut rebound = genesis.clone();
        rebound.witness_origin_digest = "77".repeat(32);
        assert!(validate_projection_pair(Some(&genesis), None, Some(&rebound), None).is_err());
    }
}
