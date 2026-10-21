//! Coordinated currentness is not permission to replay private original rows.
//! This leaf separates public identity/revision samples from genuine Read audit.
use super::*;
use wholepact_financial_coordinator_origin::SignerFinancialReadFinalV1;

impl SignerConsentJournal {
    /// Metadata/SQLite handle and revision checks only. No semantic table,
    /// enrollment, intent, private row digest or transaction is read here.
    pub(crate) fn check_coordinated_public_pin_v2(
        &self,
        source: &FinancialSourceBindingV1,
    ) -> Result<()> {
        let _fence = self
            .authority_fence
            .read()
            .map_err(|_| JournalError::Permission)?;
        let c = self.connection.lock().map_err(|_| JournalError::Database)?;
        if source.continuation_digest.is_some() || !c.is_autocommit() {
            return Err(JournalError::Conflict);
        }
        source.require(self, &c)?;
        // Do not call require_pin: its financial20 branch reads private intent.
        if source.revision != revision(&c)? {
            return Err(JournalError::Conflict);
        }
        source.require(self, &c)
    }

    /// The full original19 audit belongs to the concrete still-current Read.
    /// Check immediately after each blocking acquisition before private reads.
    pub(crate) fn check_coordinated_read_source_v2(
        &self,
        source: &FinancialSourceBindingV1,
        read: &SignerFinancialReadFinalV1,
    ) -> Result<()> {
        let check = || -> Result<()> {
            read.check_current().map_err(|_| JournalError::Permission)?;
            if read.presentation().facts.source_identity_digest != source.identity_digest()
                || source.continuation_digest.is_some()
            {
                return Err(JournalError::Permission);
            }
            Ok(())
        };
        check()?;
        let _fence = self
            .authority_fence
            .read()
            .map_err(|_| JournalError::Permission)?;
        check()?;
        let mut c = self.connection.lock().map_err(|_| JournalError::Database)?;
        check()?;
        source.require(self, &c)?;
        check()?;
        source.require_pin(&c)?;
        check()?;
        let tx = c.transaction_with_behavior(TransactionBehavior::Deferred)?;
        check()?;
        original_delivery::validate(&tx, &source.genesis, self.capacity_limits())?;
        check()?;
        if original_rows_digest(&tx)? != source.original_rows_digest {
            return Err(JournalError::Conflict);
        }
        check()?;
        source.require(self, &tx)?;
        check()?;
        source.require_pin(&tx)?;
        check()?;
        tx.commit()?;
        check()?;
        source.require_pin(&c)?;
        check()
    }
}

impl FinancialConsentJournalV1 {
    /// Metadata only, including for profile20: never require_pin's intent read.
    pub(crate) fn check_coordinated_public_pin_v2(
        &self,
        source: &FinancialSourceBindingV1,
    ) -> Result<()> {
        let _fence = self
            .journal
            .authority_fence
            .read()
            .map_err(|_| JournalError::Permission)?;
        let c = self
            .journal
            .connection
            .lock()
            .map_err(|_| JournalError::Database)?;
        if source.continuation_digest.is_none()
            || source.genesis != self.genesis
            || !c.is_autocommit()
        {
            return Err(JournalError::Conflict);
        }
        source.require(&self.journal, &c)?;
        if source.revision != revision(&c)? {
            return Err(JournalError::Conflict);
        }
        source.require(&self.journal, &c)
    }

    /// The only input is the sealed Pending returned by the successful actual
    /// guarded transaction. No DTO, caller row digest or new private audit.
    /// It already holds the exact committed rows, intent and revision sampled
    /// while Final was retained. Fresh random identity is data, not permission.
    pub(crate) fn binding_from_coordinated_commit_v2(
        &self,
        pending: &PendingFinancialContinuationAdmissionV1,
        original_identity: &str,
    ) -> Result<FinancialSourceBindingV1> {
        let source = &pending.source;
        let continuation_digest = pending.retained.history_digest()?;
        if Arc::strong_count(&self.journal.source_registration) != 1
            || source.source_digest != original_identity
            || source.genesis != self.genesis
            || source.journal != self.journal.binding()
            || source.identity != self.journal.database_identity
            || source.continuation_digest.as_ref() != Some(&continuation_digest)
            || source.revision.user_version != VERSION
        {
            return Err(JournalError::Conflict);
        }
        hash(&source.original_rows_digest)?;
        hash(original_identity)?;
        pending
            .retained
            .terms()?
            .require_live(now_ms()?)
            .map_err(|_| JournalError::Expired)?;
        let _fence = self
            .journal
            .authority_fence
            .read()
            .map_err(|_| JournalError::Permission)?;
        let c = self
            .journal
            .connection
            .lock()
            .map_err(|_| JournalError::Database)?;
        source.require(&self.journal, &c)?;
        if !c.is_autocommit() || source.revision != revision(&c)? {
            return Err(JournalError::Conflict);
        }
        let binding = FinancialSourceBindingV1 {
            journal: source.journal.clone(),
            identity: source.identity.clone(),
            genesis: source.genesis.clone(),
            source_digest: digest(
                "wholepact:original-financial-source:v1",
                &(
                    &self.genesis,
                    &source.original_rows_digest,
                    &continuation_digest,
                    random_id()?,
                ),
            )?,
            original_rows_digest: source.original_rows_digest.clone(),
            continuation_digest: Some(continuation_digest),
            revision: FinancialJournalRevisionV1 {
                data_version: source.revision.data_version,
                total_changes: source.revision.total_changes,
                schema_version: source.revision.schema_version,
                user_version: source.revision.user_version,
            },
        };
        source.require(&self.journal, &c)?;
        if source.revision != revision(&c)? {
            return Err(JournalError::Conflict);
        }
        Ok(binding)
    }
}

impl SignerConsentJournal {
    /// Exact original binding factory under the still-live genuine Entry. The
    /// actual account/genesis/root remain the private source opener's custody.
    pub(crate) fn prepare_coordinated_entry_source_binding_v2(
        &self,
        genesis: &AccountUseGenesis,
        entry: &wholepact_financial_coordinator_origin::SignerSourceEntryFinalV1,
    ) -> Result<FinancialSourceBindingV1> {
        let check = || entry.check_current().map_err(|_| JournalError::Permission);
        check()?;
        let _fence = self
            .authority_fence
            .read()
            .map_err(|_| JournalError::Permission)?;
        check()?;
        let mut c = self.connection.lock().map_err(|_| JournalError::Database)?;
        check()?;
        self.database_identity.check_current(&c)?;
        check()?;
        let before = revision(&c)?;
        check()?;
        let tx = c.transaction_with_behavior(TransactionBehavior::Deferred)?;
        check()?;
        original_delivery::validate(&tx, genesis, self.capacity_limits())?;
        check()?;
        if financial_admission_intents::read_all(&tx)?.len() != 1 {
            return Err(JournalError::RecoveryRequired);
        }
        check()?;
        let original_rows_digest = original_rows_digest(&tx)?;
        check()?;
        self.database_identity.check_current(&tx)?;
        check()?;
        tx.commit()?;
        check()?;
        if revision(&c)? != before {
            return Err(JournalError::Conflict);
        }
        check()?;
        Ok(FinancialSourceBindingV1 {
            journal: self.binding(),
            identity: self.database_identity.clone(),
            genesis: genesis.clone(),
            source_digest: digest(
                "wholepact:original-financial-source:v1",
                &(genesis, &original_rows_digest, random_id()?),
            )?,
            original_rows_digest,
            continuation_digest: None,
            revision: before,
        })
    }

    pub(crate) fn check_coordinated_entry_source_v2(
        &self,
        source: &FinancialSourceBindingV1,
        entry: &wholepact_financial_coordinator_origin::SignerSourceEntryFinalV1,
    ) -> Result<()> {
        let check = || entry.check_current().map_err(|_| JournalError::Permission);
        check()?;
        if source.continuation_digest.is_some() {
            return Err(JournalError::Conflict);
        }
        let _fence = self
            .authority_fence
            .read()
            .map_err(|_| JournalError::Permission)?;
        check()?;
        let mut c = self.connection.lock().map_err(|_| JournalError::Database)?;
        check()?;
        source.require(self, &c)?;
        check()?;
        source.require_pin(&c)?;
        check()?;
        let tx = c.transaction_with_behavior(TransactionBehavior::Deferred)?;
        check()?;
        original_delivery::validate(&tx, &source.genesis, self.capacity_limits())?;
        check()?;
        if original_rows_digest(&tx)? != source.original_rows_digest {
            return Err(JournalError::Conflict);
        }
        check()?;
        source.require(self, &tx)?;
        check()?;
        source.require_pin(&tx)?;
        check()?;
        tx.commit()?;
        check()?;
        source.require_pin(&c)?;
        check()
    }
}
