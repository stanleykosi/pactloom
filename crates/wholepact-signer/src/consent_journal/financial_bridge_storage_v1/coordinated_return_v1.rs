//! Fresh coordinated ReturnRead over the same original profile20 journal.
//! The common rows/pin are inert; no native Read lease is constructed.
use super::*;
use wholepact_financial_coordinator_origin::SignerReturnReadFinalV1;

impl FinancialConsentJournalV1 {
    pub(crate) fn coordinated_financial_retained_result_v1(
        &self,
        source: &FinancialSourceBindingV1,
        read: &SignerReturnReadFinalV1,
    ) -> BridgeResult<(
        OriginalAuthorizationEvidence,
        RetainedAuthorizationRequest,
        RetainedWitnessPermit,
        RetainedAuthorizationResult,
        FinancialReturnJournalPinV1,
        wholepact_authority::OwnerControlRequest,
    )> {
        let check = || -> BridgeResult<()> {
            read.check_current().map_err(|_| BridgeError::Permission)?;
            if read
                .presentation()
                .facts
                .original
                .activation
                .facts
                .original
                .source_identity_digest
                != source.identity_digest()
            {
                return Err(BridgeError::Binding);
            }
            Ok(())
        };
        check()?;
        let _fence = self
            .journal
            .authority_fence
            .read()
            .map_err(|_| JournalError::Permission)?;
        check()?;
        let mut c = self
            .journal
            .connection
            .lock()
            .map_err(|_| JournalError::Database)?;
        check()?;
        if !c.is_autocommit() {
            return Err(JournalError::Conflict.into());
        }
        source.require(&self.journal, &c)?;
        source.require_pin(&c)?;
        let tx = c
            .transaction_with_behavior(TransactionBehavior::Deferred)
            .map_err(JournalError::from)?;
        check()?;
        // Strict entire-namespace profile selection; never retry another decoder.
        if !matches!(
            original_delivery::profile(&tx)?,
            durable_born_entry_v1::OriginalDeliveryProfileV1::CoordinatedV3
        ) {
            return Err(BridgeError::Binding);
        }
        validate(&tx, &self.genesis)?;
        check()?;
        let (original, request, permit, result, retained) = read_retained_result_rows(&tx)?;
        let signed = &read.presentation().facts.signed;
        if signed.authorization_id != result.authorization_id
            || signed.original_consent_ref != result.original_consent_ref
            || signed.result_digest != result.result_digest
            || signed.outbox_digest != result.outbox_digest
        {
            return Err(BridgeError::Binding);
        }
        source.require(&self.journal, &tx)?;
        source.require_pin(&tx)?;
        let original_delivery =
            authority::durable_delivery_admission_intent_v3::coordinated_v1::read(
                &tx,
                &result.authorization_id,
            )?
            .ok_or(BridgeError::Missing)?;
        let host = &original_delivery
            .recipient_intent()
            .authorized_host_process_instance;
        if host != &read.presentation().facts.original_host_process_instance {
            return Err(BridgeError::Binding);
        }
        let pin = FinancialReturnJournalPinV1::from_audited_result(
            self,
            source,
            &tx,
            host.clone(),
            result.result_digest.clone(),
        )?;
        check()?;
        tx.commit().map_err(JournalError::from)?;
        check()?;
        source.require_pin(&c)?;
        if !c.is_autocommit() {
            return Err(JournalError::Conflict.into());
        }
        pin.require(self, source, &c)?;
        check()?;
        Ok((
            original,
            request,
            permit,
            result,
            pin,
            retained.request().clone(),
        ))
    }
}
