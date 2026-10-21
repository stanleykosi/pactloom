//! Same original journal snapshot under actual fresh V3 Audit, before completion.
//! Returned binding is inert selection evidence, never permission to read again.
use super::*;
use authority::durable_delivery_admission_intent_v3::coordinated_v1::RetainedCoordinatedAdmissionIntentV1;
use wholepact_financial_coordinator_origin::SignerV3AuditFinalV1;
impl SignerConsentJournal {
    pub(crate) fn prepare_coordinated_v3_audit_source_binding_v1(
        &self, genesis: &AccountUseGenesis, source_identity: &str,
        retained: &RetainedCoordinatedAdmissionIntentV1, action: &SignerV3AuditFinalV1,
    ) -> Result<FinancialSourceBindingV1> {
        let check = || -> Result<()> {
            action.check_current().map_err(|_| JournalError::Permission)?;
            if action.facts().received.source_identity_digest != source_identity
                || action.facts().received.recipient_intent_digest != retained.recipient_intent_digest()?
                || action.facts().admitted.local_record_digest != retained.history_digest()?
                || action.facts().operation_id != retained.request().operation_id
            { return Err(JournalError::InvalidBinding); }
            Ok(())
        };
        check()?;
        let wholepact_authority::OwnerControl::AdmitDurablePaymentWithDeliveryV2 { record } = &retained.request().control
            else { return Err(JournalError::InvalidBinding); };
        let _fence = self.authority_fence.read().map_err(|_| JournalError::Permission)?;
        check()?;
        let mut c = self.connection.lock().map_err(|_| JournalError::Database)?;
        check()?;
        self.database_identity.check_current(&c)?;
        let before = revision(&c)?;
        let tx = c.transaction_with_behavior(TransactionBehavior::Deferred)?;
        check()?;
        durable_born_entry_v1::validate_coordinated_delivery_v1(&tx, genesis, self.capacity_limits())?;
        check()?;
        let actual = authority::durable_delivery_admission_intent_v3::coordinated_v1::read(
            &tx, &record.scope.authorization.authorization_id,
        )?.ok_or(JournalError::NotFound)?;
        if &actual != retained { return Err(JournalError::Conflict); }
        let original_rows_digest = original_rows_digest(&tx)?;
        self.database_identity.check_current(&tx)?;
        check()?;
        tx.commit()?;
        check()?;
        if revision(&c)? != before { return Err(JournalError::Conflict); }
        Ok(FinancialSourceBindingV1 {
            journal: self.binding(), identity: self.database_identity.clone(), genesis: genesis.clone(),
            source_digest: digest("wholepact:original-financial-source:v1", &(genesis, &original_rows_digest, random_id()?))?,
            original_rows_digest, continuation_digest: None, revision: before,
        })
    }
}
