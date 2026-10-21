//! Actual original19 revision custody under the distinct V3 SourceEntry.
//! Reuses maintained SQL interpretation; resamples the nominal token after
//! each acquired fence/connection and before private audit/snapshot/commit.
use super::*;
use wholepact_financial_coordinator_origin::{
    SignerV3AdmitReadFinalV1, SignerV3PrepareReadFinalV1, SignerV3RedisclosureReadFinalV1,
    SignerV3SourceEntryFinalV1,
};
// Closed nominal purposes only. A cached lifetime or boolean cannot enter SQL.
enum ReadPermit<'a> {
    Entry(&'a SignerV3SourceEntryFinalV1),
    Redisclosure(&'a SignerV3RedisclosureReadFinalV1),
    Prepare(&'a SignerV3PrepareReadFinalV1),
    AdmitRead(&'a SignerV3AdmitReadFinalV1),
}
impl ReadPermit<'_> {
    fn current(&self) -> Result<()> {
        match self {
            Self::Entry(value) => value.check_current(),
            Self::Redisclosure(value) => value.check_current(),
            Self::Prepare(value) => value.check_current(),
            Self::AdmitRead(value) => value.check_current(),
        }
        .map_err(|_| JournalError::Permission)
    }
}
fn current(entry: &SignerV3SourceEntryFinalV1) -> Result<()> {
    entry.check_current().map_err(|_| JournalError::Permission)
}
impl SignerConsentJournal {
    fn sample_coordinated_v3_entry(
        &self,
        genesis: &AccountUseGenesis,
        enrollment: &str,
        manifest: &str,
        entry: &ReadPermit<'_>,
    ) -> Result<(DatabaseRevisionV3, ScopedStateV3)> {
        entry.current()?;
        let _fence = self
            .authority_fence
            .read()
            .map_err(|_| JournalError::Permission)?;
        entry.current()?;
        self.require_prepared_delivery_file_v3()?;
        entry.current()?;
        let mut c = self.connection.lock().map_err(|_| JournalError::Database)?;
        entry.current()?;
        if !c.is_autocommit() {
            return Err(JournalError::Database);
        }
        self.database_identity.check_current(&c)?;
        entry.current()?;
        let before = revision(&c)?;
        entry.current()?;
        if before.application_id != APPLICATION_ID || before.user_version != SCHEMA_VERSION {
            return Err(JournalError::UnsupportedSchema);
        }
        let tx = c.transaction_with_behavior(TransactionBehavior::Deferred)?;
        entry.current()?;
        let state = scoped_state(&tx, genesis, enrollment, manifest)?;
        entry.current()?;
        if revision(&tx)? != before {
            return Err(JournalError::Conflict);
        }
        entry.current()?;
        self.database_identity.check_current(&tx)?;
        entry.current()?;
        tx.commit()?;
        entry.current()?;
        if revision(&c)? != before {
            return Err(JournalError::Conflict);
        }
        entry.current()?;
        self.database_identity.check_current(&c)?;
        entry.current()?;
        self.require_prepared_delivery_file_v3()?;
        entry.current()?;
        Ok((before, state))
    }

    pub(crate) fn prepare_coordinated_v3_entry_revision(
        &self,
        genesis: &AccountUseGenesis,
        enrollment: &str,
        manifest: &str,
        entry: &SignerV3SourceEntryFinalV1,
    ) -> Result<(
        PreparedDeliveryJournalRevisionV3,
        AccountEnrollmentRecord,
        AcceptedManifestRecord,
    )> {
        hash(enrollment)?;
        hash(manifest)?;
        current(entry)?;
        let before = self.sample_coordinated_v3_entry(
            genesis,
            enrollment,
            manifest,
            &ReadPermit::Entry(entry),
        )?;
        {
            current(entry)?;
            let _fence = self
                .authority_fence
                .read()
                .map_err(|_| JournalError::Permission)?;
            current(entry)?;
            let mut c = self.connection.lock().map_err(|_| JournalError::Database)?;
            current(entry)?;
            if !c.is_autocommit() {
                return Err(JournalError::Database);
            }
            self.database_identity.check_current(&c)?;
            current(entry)?;
            let tx = c.transaction_with_behavior(TransactionBehavior::Deferred)?;
            current(entry)?;
            durable_born_entry_v1::validate_delivery_v3(&tx, genesis, self.capacity_limits())?;
            current(entry)?;
            self.database_identity.check_current(&tx)?;
            current(entry)?;
            tx.commit()?;
            current(entry)?;
        }
        let after = self.sample_coordinated_v3_entry(
            genesis,
            enrollment,
            manifest,
            &ReadPermit::Entry(entry),
        )?;
        if before != after {
            return Err(JournalError::Conflict);
        }
        current(entry)?;
        let records = (after.1.enrollment.clone(), after.1.manifest.clone());
        let pin = PreparedDeliveryJournalRevisionV3 {
            journal: self.binding(),
            registration: Arc::clone(&self.source_registration),
            genesis: genesis.clone(),
            revision: after.0,
            state: after.1,
        };
        current(entry)?;
        Ok((pin, records.0, records.1))
    }
    pub(crate) fn check_coordinated_v3_redisclosure_revision(
        &self,
        prepared: &PreparedDeliveryJournalRevisionV3,
        read: &SignerV3RedisclosureReadFinalV1,
    ) -> Result<()> {
        let permit = ReadPermit::Redisclosure(read);
        permit.current()?;
        if prepared.journal != self.binding()
            || !Arc::ptr_eq(&prepared.registration, &self.source_registration)
        {
            return Err(JournalError::Permission);
        }
        let current = self.sample_coordinated_v3_entry(
            &prepared.genesis,
            prepared.state.enrollment.reference(),
            prepared.state.manifest.reference(),
            &permit,
        )?;
        if current.0 != prepared.revision || current.1 != prepared.state {
            return Err(JournalError::Conflict);
        }
        permit.current()
    }
    pub(crate) fn check_coordinated_v3_prepare_revision(
        &self,
        prepared: &PreparedDeliveryJournalRevisionV3,
        read: &SignerV3PrepareReadFinalV1,
    ) -> Result<()> {
        let permit = ReadPermit::Prepare(read);
        permit.current()?;
        if prepared.journal != self.binding()
            || !Arc::ptr_eq(&prepared.registration, &self.source_registration)
        {
            return Err(JournalError::Permission);
        }
        let current = self.sample_coordinated_v3_entry(
            &prepared.genesis,
            prepared.state.enrollment.reference(),
            prepared.state.manifest.reference(),
            &permit,
        )?;
        if current.0 != prepared.revision || current.1 != prepared.state {
            return Err(JournalError::Conflict);
        }
        permit.current()
    }
    pub(crate) fn check_coordinated_v3_admit_read_revision(
        &self,
        prepared: &PreparedDeliveryJournalRevisionV3,
        read: &SignerV3AdmitReadFinalV1,
    ) -> Result<()> {
        let permit = ReadPermit::AdmitRead(read);
        permit.current()?;
        if prepared.journal != self.binding()
            || !Arc::ptr_eq(&prepared.registration, &self.source_registration)
        {
            return Err(JournalError::Permission);
        }
        let current = self.sample_coordinated_v3_entry(
            &prepared.genesis,
            prepared.state.enrollment.reference(),
            prepared.state.manifest.reference(),
            &permit,
        )?;
        if current.0 != prepared.revision || current.1 != prepared.state {
            return Err(JournalError::Conflict);
        }
        permit.current()
    }
}
