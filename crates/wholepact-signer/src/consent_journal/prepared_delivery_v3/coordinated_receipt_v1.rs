//! Exact coordinated fresh-receipt append on the retained original connection.
use super::*;
use wholepact_financial_coordinator_origin::{SignerV3EnrollmentFinalV1, SignerV3ManifestFinalV1};
pub(in crate::consent_journal) enum CoordinatedReceiptActionV1<'a> {
    Enrollment(&'a SignerV3EnrollmentFinalV1),
    Manifest(&'a SignerV3ManifestFinalV1),
}
impl CoordinatedReceiptActionV1<'_> {
    pub(in crate::consent_journal) fn check(&self) -> Result<()> {
        match self {
            Self::Enrollment(v) => v.check_current(),
            Self::Manifest(v) => v.check_current(),
        }
        .map_err(|_| JournalError::Permission)
    }
    fn execute(&self, work: impl FnOnce() -> std::io::Result<()>) -> Result<()> {
        match self {
            Self::Enrollment(value) => value.execute_enrollment_publication(work),
            Self::Manifest(value) => value.execute_manifest_publication(work),
        }
        .map_err(|_| JournalError::Permission)
    }
}
impl SignerConsentJournal {
    pub(in crate::consent_journal) fn with_coordinated_receipt_effect_v1<T, F>(
        &self,
        mut pin: PreparedDeliveryJournalRevisionV3,
        action: CoordinatedReceiptActionV1<'_>,
        prepare: impl FnOnce(&rusqlite::Transaction<'_>) -> Result<F>,
    ) -> Result<(T, Result<PreparedDeliveryJournalRevisionV3>)>
    where F: FnOnce(&rusqlite::Transaction<'_>) -> Result<T>,
    {
        action.check()?;
        if pin.journal != self.binding()
            || !Arc::ptr_eq(&pin.registration, &self.source_registration)
        {
            return Err(JournalError::Permission);
        }
        let _fence = self
            .authority_fence
            .write()
            .map_err(|_| JournalError::Permission)?;
        action.check()?;
        self.require_prepared_delivery_file_v3()?;
        let mut c = self.connection.lock().map_err(|_| JournalError::Database)?;
        action.check()?;
        if !c.is_autocommit() {
            return Err(JournalError::Database);
        }
        self.database_identity.check_current(&c)?;
        if revision(&c)? != pin.revision {
            return Err(JournalError::Conflict);
        }
        let tx = c.transaction_with_behavior(TransactionBehavior::Immediate)?;
        action.check()?;
        if revision(&tx)? != pin.revision
            || scoped_state(
                &tx,
                &pin.genesis,
                pin.state.enrollment.reference(),
                pin.state.manifest.reference(),
            )? != pin.state
        {
            return Err(JournalError::Conflict);
        }
        // Acquire and validate the exact session/nonce leases before entering
        // the publication gate. The returned effect contains no later lock wait.
        let effect = prepare(&tx)?;
        action.check()?;
        let mut outcome = None;
        let slot = &mut outcome;
        let prior = &pin;
        // The transaction is MOVED into this synchronous gate callback. On
        // every error/panic its rollback/destructor precedes gate release.
        let gate = action.execute(move || {
            let result = (|| -> Result<(T, DatabaseRevisionV3)> {
                let result = effect(&tx)?;
                let after = revision(&tx)?;
                if after.data_version != prior.revision.data_version
                    || after.schema_version != prior.revision.schema_version
                    || after.application_id != prior.revision.application_id
                    || after.user_version != prior.revision.user_version
                    || after
                        .total_changes
                        .checked_sub(prior.revision.total_changes)
                        != Some(1)
                    || scoped_state(
                        &tx,
                        &prior.genesis,
                        prior.state.enrollment.reference(),
                        prior.state.manifest.reference(),
                    )? != prior.state
                {
                    return Err(JournalError::Conflict);
                }
                self.database_identity.check_current(&tx)?;
                self.require_prepared_delivery_file_v3()?;
                tx.commit()?;
                Ok((result, after))
            })();
            let succeeded = result.is_ok();
            *slot = Some(result);
            if succeeded {
                Ok(())
            } else {
                Err(std::io::Error::new(
                    std::io::ErrorKind::PermissionDenied,
                    "coordinated receipt publication failed",
                ))
            }
        });
        // The committed record survives every later restriction/postcheck.
        // An invalid postcommit pin is withheld, never restored or retried.
        let (result, after) = outcome.ok_or(JournalError::Permission)??;
        let checked_pin = (|| -> Result<PreparedDeliveryJournalRevisionV3> {
            gate?;
            action.check()?;
            if revision(&c)? != after { return Err(JournalError::Conflict); }
            self.database_identity.check_current(&c)?;
            pin.revision = after;
            Ok(pin)
        })();
        Ok((result, checked_pin))
    }
}
