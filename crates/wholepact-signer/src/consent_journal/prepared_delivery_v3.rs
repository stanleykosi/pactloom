//! A retained interpretation of one actual encrypted journal, not read or
//! mutation permission. SQLite revision values are compared only on the SAME
//! held connection. This is sampled change detection, not writer exclusion.
use super::*;
use wholepact_authority::account_use::AccountUseGenesis;

#[derive(PartialEq, Eq)]
struct DatabaseRevisionV3 {
    data_version: i64,
    total_changes: i64,
    schema_version: i64,
    application_id: i64,
    user_version: i64,
}

#[derive(PartialEq, Eq)]
struct ScopedStateV3 {
    account: SignerAccountState,
    enrollment: AccountEnrollmentRecord,
    manifest: AcceptedManifestRecord,
}

/// No Clone, serialization, raw connection, permission or public row accessor.
/// A copied account ID or a revision read from a different connection cannot
/// recreate this owner. Its original full validation does not renew consent.
pub(crate) struct PreparedDeliveryJournalRevisionV3 {
    journal: SignerJournalBinding,
    registration: Arc<LiveCurrent19Source>,
    genesis: AccountUseGenesis,
    revision: DatabaseRevisionV3,
    state: ScopedStateV3,
}

fn revision(c: &Connection) -> Result<DatabaseRevisionV3> {
    Ok(DatabaseRevisionV3 {
        data_version: c.pragma_query_value(None, "data_version", |r| r.get(0))?,
        total_changes: c.query_row("SELECT total_changes()", [], |r| r.get(0))?,
        schema_version: c.pragma_query_value(None, "schema_version", |r| r.get(0))?,
        application_id: c.pragma_query_value(None, "application_id", |r| r.get(0))?,
        user_version: c.pragma_query_value(None, "user_version", |r| r.get(0))?,
    })
}

fn scoped_state(
    c: &Connection,
    genesis: &AccountUseGenesis,
    enrollment_ref: &str,
    manifest_ref: &str,
) -> Result<ScopedStateV3> {
    if c.is_autocommit() {
        return Err(JournalError::InvalidBinding);
    }
    let account = read_account(c)?;
    let original = account_use_storage::inspect(c, &account.account_id)?;
    if account.account_id != genesis.identity.account_id
        || original.genesis() != Some(genesis)
        || original.exclusion().is_some()
        || original.witness_ack().is_some()
    {
        return Err(JournalError::Permission);
    }
    if account.recovery_required {
        return Err(JournalError::RecoveryRequired);
    }
    let enrollment = read_enrollment(c, enrollment_ref)?.ok_or(JournalError::NotFound)?;
    let manifest = read_manifest(c, manifest_ref)?.ok_or(JournalError::NotFound)?;
    if enrollment.account_id() != account.account_id
        || manifest.terms.account_id != account.account_id
        || manifest.enrollment_ref() != enrollment.reference()
        || manifest.terms.principal_id != enrollment.principal_id()
        || enrollment.receipt().writer_epoch() != account.writer_epoch
        || manifest.receipt().writer_epoch() != account.writer_epoch
        || !same_native_origin(enrollment.receipt(), manifest.receipt())
    {
        return Err(JournalError::Permission);
    }
    // This narrow profile never authorizes sponsor-policy rows. The full
    // initial validator establishes this; checking the relevant tables again
    // in each actual snapshot denies a later cross-handle policy insertion.
    for table in [
        "signer_sponsor_policy_events",
        "signer_sponsor_manifest_bindings",
    ] {
        let present: bool = c.query_row(
            &format!("SELECT EXISTS(SELECT 1 FROM {table})"),
            [],
            |r| r.get(0),
        )?;
        if present {
            return Err(JournalError::Permission);
        }
    }
    Ok(ScopedStateV3 { account, enrollment, manifest })
}

impl SignerConsentJournal {
    fn require_prepared_delivery_file_v3(&self) -> Result<()> {
        self.source_registration.owner.directory.check_current()
            .map_err(|_| JournalError::Permission)?;
        if self.source_registration.identity != self.database_identity {
            return Err(JournalError::InvalidBinding);
        }
        Ok(())
    }

    fn sample_prepared_delivery_v3(
        &self,
        genesis: &AccountUseGenesis,
        enrollment_ref: &str,
        manifest_ref: &str,
    ) -> Result<(DatabaseRevisionV3, ScopedStateV3)> {
        let _fence = self.authority_fence.read().map_err(|_| JournalError::Permission)?;
        self.require_prepared_delivery_file_v3()?;
        let mut c = self.connection.lock().map_err(|_| JournalError::Database)?;
        if !c.is_autocommit() {
            return Err(JournalError::Database);
        }
        self.database_identity.check_current(&c)?;
        let before = revision(&c)?;
        if before.application_id != APPLICATION_ID || before.user_version != SCHEMA_VERSION {
            return Err(JournalError::UnsupportedSchema);
        }
        let tx = c.transaction_with_behavior(TransactionBehavior::Deferred)?;
        let state = scoped_state(&tx, genesis, enrollment_ref, manifest_ref)?;
        if revision(&tx)? != before {
            return Err(JournalError::Conflict);
        }
        self.database_identity.check_current(&tx)?;
        tx.commit()?;
        // A WAL writer can commit while our read snapshot is retained. Check
        // again after ending it, rather than calling a frozen view "current".
        if revision(&c)? != before {
            return Err(JournalError::Conflict);
        }
        self.database_identity.check_current(&c)?;
        self.require_prepared_delivery_file_v3()?;
        Ok((before, state))
    }

    /// Full original historical interpretation occurs once between revision
    /// samples. Any same-connection or independent-handle mutation invalidates
    /// preparation, including mutation that restores the same logical values.
    pub(crate) fn prepare_delivery_journal_revision_v3(
        &self,
        genesis: &AccountUseGenesis,
        enrollment_ref: &str,
        manifest_ref: &str,
    ) -> Result<PreparedDeliveryJournalRevisionV3> {
        hash(enrollment_ref)?;
        hash(manifest_ref)?;
        let before = self.sample_prepared_delivery_v3(genesis, enrollment_ref, manifest_ref)?;
        self.check_durable_delivery_entry_v3(genesis)?;
        let after = self.sample_prepared_delivery_v3(genesis, enrollment_ref, manifest_ref)?;
        if before != after {
            return Err(JournalError::Conflict);
        }
        Ok(PreparedDeliveryJournalRevisionV3 {
            journal: self.binding(),
            registration: Arc::clone(&self.source_registration),
            genesis: genesis.clone(),
            revision: after.0,
            state: after.1,
        })
    }

    pub(crate) fn refresh_delivery_journal_revision_v3(
        &self, previous: PreparedDeliveryJournalRevisionV3,
    ) -> Result<PreparedDeliveryJournalRevisionV3> {
        self.check_delivery_journal_revision_v3(&previous)?;
        let fresh = self.prepare_delivery_journal_revision_v3(&previous.genesis, previous.state.enrollment.reference(), previous.state.manifest.reference())?;
        self.check_delivery_journal_revision_v3(&previous)?;
        if fresh.revision != previous.revision || fresh.state != previous.state { return Err(JournalError::Conflict); }
        Ok(fresh)
    }

    pub(crate) fn prepared_delivery_original_records_v3(
        &self, pin: &PreparedDeliveryJournalRevisionV3,
    ) -> Result<(AccountEnrollmentRecord, AcceptedManifestRecord)> {
        self.check_delivery_journal_revision_v3(pin)?;
        let records = (pin.state.enrollment.clone(), pin.state.manifest.clone());
        self.check_delivery_journal_revision_v3(pin)?;
        Ok(records)
    }

    pub(crate) fn check_delivery_journal_revision_v3(
        &self,
        prepared: &PreparedDeliveryJournalRevisionV3,
    ) -> Result<()> {
        if prepared.journal != self.binding()
            || !Arc::ptr_eq(&prepared.registration, &self.source_registration)
        {
            return Err(JournalError::Permission);
        }
        let current = self.sample_prepared_delivery_v3(
            &prepared.genesis,
            prepared.state.enrollment.reference(),
            prepared.state.manifest.reference(),
        )?;
        if current.0 != prepared.revision || current.1 != prepared.state {
            return Err(JournalError::Conflict);
        }
        Ok(())
    }

    /// Only the closed journal adapter may supply the typed insertion. This
    /// method owns the actual connection and Immediate transaction, so no
    /// foreign-connection revision or caller-asserted held fence can be used.
    /// Consuming the prior pin prevents reusing it after any attempted effect.
    pub(in crate::consent_journal) fn with_delivery_journal_effect_v3<T>(
        &self,
        mut prepared: PreparedDeliveryJournalRevisionV3,
        effect: impl FnOnce(&rusqlite::Transaction<'_>) -> Result<T>,
    ) -> Result<(T, PreparedDeliveryJournalRevisionV3)> {
        if prepared.journal != self.binding()
            || !Arc::ptr_eq(&prepared.registration, &self.source_registration)
        {
            return Err(JournalError::Permission);
        }
        let _fence = self.authority_fence.write().map_err(|_| JournalError::Permission)?;
        self.require_prepared_delivery_file_v3()?;
        let mut c = self.connection.lock().map_err(|_| JournalError::Database)?;
        if !c.is_autocommit() {
            return Err(JournalError::Database);
        }
        self.database_identity.check_current(&c)?;
        if revision(&c)? != prepared.revision {
            return Err(JournalError::Conflict);
        }
        let tx = c.transaction_with_behavior(TransactionBehavior::Immediate)?;
        if revision(&tx)? != prepared.revision
            || scoped_state(
                &tx,
                &prepared.genesis,
                prepared.state.enrollment.reference(),
                prepared.state.manifest.reference(),
            )? != prepared.state
        {
            return Err(JournalError::Conflict);
        }
        let result = effect(&tx)?;
        let after = revision(&tx)?;
        if after.data_version != prepared.revision.data_version
            || after.schema_version != prepared.revision.schema_version
            || after.application_id != prepared.revision.application_id
            || after.user_version != prepared.revision.user_version
            || !matches!(after.total_changes.checked_sub(prepared.revision.total_changes), Some(0 | 1))
            || scoped_state(&tx, &prepared.genesis, prepared.state.enrollment.reference(), prepared.state.manifest.reference())? != prepared.state
        {
            return Err(JournalError::Conflict);
        }
        self.database_identity.check_current(&tx)?;
        self.require_prepared_delivery_file_v3()?;
        tx.commit()?;
        // Never adopt a racing independent writer's revision as our own. A
        // failure here is postcommit uncertainty; the consumed old pin is gone.
        if revision(&c)? != after { return Err(JournalError::Conflict); }
        self.database_identity.check_current(&c)?;
        prepared.revision = after;
        Ok((result, prepared))
    }
}
