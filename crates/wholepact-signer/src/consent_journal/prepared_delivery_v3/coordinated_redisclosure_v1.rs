//! A new coordinated redisclosure row under the actual held preconstruction lease.
use super::*;
use wholepact_financial_coordinator_origin::SignerV3RediscloseFinalV1;
impl SignerConsentJournal {
    pub(in crate::consent_journal) fn with_coordinated_redisclosure_effect_v1<T>(
        &self,
        mut pin: PreparedDeliveryJournalRevisionV3,
        lease: &PreconstructionRecordLease<'_>,
        action: &SignerV3RediscloseFinalV1,
        effect: impl FnOnce(&rusqlite::Transaction<'_>) -> Result<T>,
    ) -> Result<(T, PreparedDeliveryJournalRevisionV3)> {
        let current = || action.check_current().map_err(|_| JournalError::Permission);
        current()?;
        lease.require_journal(&self.binding())?;
        lease.require_current_durable_disclosure_receipts_v1()?;
        if pin.journal != self.binding()
            || !Arc::ptr_eq(&pin.registration, &self.source_registration)
        {
            return Err(JournalError::Permission);
        }
        // The genuine lease ALREADY holds the account authority read fence;
        // acquiring a second write fence here would deadlock, not strengthen it.
        self.require_prepared_delivery_file_v3()?;
        let mut c = self.connection.lock().map_err(|_| JournalError::Database)?;
        current()?;
        if !c.is_autocommit() {
            return Err(JournalError::Database);
        }
        self.database_identity.check_current(&c)?;
        if revision(&c)? != pin.revision {
            return Err(JournalError::Conflict);
        }
        let tx = c.transaction_with_behavior(TransactionBehavior::Immediate)?;
        current()?;
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
        // Nonce-map checks may wait: complete them BEFORE gate admission.
        lease.require_current_durable_disclosure_receipts_v1()?;
        current()?;
        let mut outcome = None;
        let slot = &mut outcome;
        let prior = &pin;
        action
            .execute_redisclosure_publication(move || {
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
                let ok = result.is_ok();
                *slot = Some(result);
                if ok {
                    Ok(())
                } else {
                    Err(std::io::Error::new(
                        std::io::ErrorKind::Other,
                        "coordinated redisclosure publication failed",
                    ))
                }
            })
            .map_err(|_| JournalError::Permission)?;
        let (result, after) = outcome.ok_or(JournalError::Permission)??;
        // Postcommit errors are uncertain; the consumed old pin is never restored.
        current()?;
        if revision(&c)? != after {
            return Err(JournalError::Conflict);
        }
        self.database_identity.check_current(&c)?;
        pin.revision = after;
        Ok((result, pin))
    }
}
