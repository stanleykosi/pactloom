//! Historical selector read and NEW immutable append; no historical grant revival.
use super::*;
use wholepact_financial_coordinator_origin::{
    SignerV3RediscloseFinalV1, SignerV3RedisclosureReadFinalV1,
};
impl SignerConsentJournal {
    pub(crate) fn read_coordinated_redisclosure_original_v1(
        &self,
        request: &DurableConstructionRedisclosureSourceV1,
        lease: &CoordinatedPurposeRecordLease<'_>,
        action: &SignerV3RedisclosureReadFinalV1,
    ) -> Result<DurableConstructionOutboxV1> {
        action
            .check_current()
            .map_err(|_| JournalError::Permission)?;
        request
            .validate()
            .map_err(|_| JournalError::InvalidBinding)?;
        lease.require_journal(&self.binding())?;
        lease.require_read(action)?;
        let selector: crate::authority_bridge::durable_construction_v1::DurableConstructionRedisclosureRequestV1 =
            serde_json::from_str(&action.facts().selector_json).map_err(|_| JournalError::InvalidBinding)?;
        selector.validate().map_err(|_| JournalError::InvalidBinding)?;
        if &selector.original != request
            || selector.enrollment_ref != lease.enrollment().reference()
            || selector.accepted_manifest_ref != lease.manifest().reference()
        {
            return Err(JournalError::InvalidBinding);
        }
        let c = self.connection.lock().map_err(|_| JournalError::Database)?;
        action
            .check_current()
            .map_err(|_| JournalError::Permission)?;
        self.database_identity.check_current(&c)?;
        let original = read(&c, &request.operation_id)?.ok_or(JournalError::NotFound)?;
        if original.redisclosure().is_some()
            || request
                .expected_request_digest
                .as_ref()
                .is_some_and(|v| v != original.request_digest())
            || original.request().scope.account_id != lease.enrollment().account_id()
            || original.request().scope.participant_id != lease.enrollment().participant_id()
            || original.request().scope.proposal != *lease.manifest().proposal_input()
        {
            return Err(JournalError::InvalidBinding);
        }
        action
            .check_current()
            .map_err(|_| JournalError::Permission)?;
        Ok(original)
    }
    pub(crate) fn append_coordinated_redisclosure_v1(
        &self,
        pin: PreparedDeliveryJournalRevisionV3,
        lease: &CoordinatedPurposeRecordLease<'_>,
        candidate: &DurableConstructionOutboxV1,
        action: &SignerV3RediscloseFinalV1,
    ) -> Result<(
        DurableConstructionOutboxV1,
        Result<PreparedDeliveryJournalRevisionV3>,
    )> {
        let facts = action.facts();
        if candidate.redisclosure().is_none()
            || candidate.request_digest() != facts.prepared.next_request_digest
            || candidate.material_digest() != facts.prepared.material_digest
            || candidate.request().enrollment_ref != lease.enrollment().reference()
            || candidate.request().accepted_manifest_ref != lease.manifest().reference()
            || candidate.recipient_transport() != lease.enrollment().transport()
            || candidate.native_review_digest != action.presentation().presentation_digest
        {
            return Err(JournalError::InvalidBinding);
        }
        self.with_coordinated_redisclosure_effect_v1(pin,lease,action,|tx| {
            // No idempotent mutation retry: an existing new operation is a conflict.
            if read_raw(tx,&candidate.request().operation_id)?.is_some() { return Err(JournalError::Conflict); }
            validate_original_rows(tx,candidate)?;
            let request=candidate.request(); let raw=encode(candidate)?;
            tx.execute("INSERT INTO signer_durable_construction_outbox(operation_id,request_digest,enrollment_ref,manifest_ref,payload) VALUES(?1,?2,?3,?4,?5)",params![request.operation_id,candidate.request_digest(),request.enrollment_ref,request.accepted_manifest_ref,raw.as_str()])?;
            storage::bounded(tx,self.capacity_limits())?;
            Ok(candidate.clone())
        })
    }
}
