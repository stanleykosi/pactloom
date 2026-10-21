//! Genuine PrepareRead loads both exact linked rows on the retained connection.
use super::*;
use crate::authority_bridge::durable_review_ipc_v3::coordinated_v1::CoordinatedPrepareClosedRecipientRequestV1;
use wholepact_financial_coordinator_origin::SignerV3PrepareReadFinalV1;
impl SignerConsentJournal {
    pub(crate) fn read_coordinated_delivery_outboxes_v1(
        &self,
        preparation: &CoordinatedPrepareClosedRecipientRequestV1,
        lease: &PreconstructionRecordLease<'_>,
        action: &SignerV3PrepareReadFinalV1,
    ) -> Result<(DurableConstructionOutboxV1, DurableConstructionOutboxV1)> {
        action
            .check_current()
            .map_err(|_| JournalError::Permission)?;
        lease.require_journal(&self.binding())?;
        lease.require_current_durable_disclosure_receipts_v1()?;
        let request = &preparation.request;
        let current = request
            .current_disclosure
            .as_ref()
            .ok_or(JournalError::InvalidBinding)?;
        let c = self.connection.lock().map_err(|_| JournalError::Database)?;
        action
            .check_current()
            .map_err(|_| JournalError::Permission)?;
        self.database_identity.check_current(&c)?;
        let original =
            read(&c, &request.own_disclosure.operation_id)?.ok_or(JournalError::NotFound)?;
        let fresh = read(&c, &current.operation_id)?.ok_or(JournalError::NotFound)?;
        fresh
            .validate_redisclosure_of(&original)
            .map_err(|_| JournalError::InvalidBinding)?;
        if original.redisclosure().is_some()
            || original.request_digest() != request.own_disclosure.expected_request_digest
            || fresh.request_digest() != current.expected_request_digest
            || fresh.request().enrollment_ref != lease.enrollment().reference()
            || fresh.request().accepted_manifest_ref != lease.manifest().reference()
            || fresh.recipient_transport() != lease.enrollment().transport()
        {
            return Err(JournalError::InvalidBinding);
        }
        action
            .check_current()
            .map_err(|_| JournalError::Permission)?;
        Ok((original, fresh))
    }
}
