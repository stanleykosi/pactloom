//! Consumes the actual verified original V3 owner, not a peer/provider factory.
use super::*;
use crate::authority_bridge::financial_continuation_v1::{
    AuthenticatedFinancialContinuationHistoryV1, FinancialResultRequestV1,
    FinancialResultRestrictionV1, PreparedFinancialResultReceiverV1,
};
impl PendingDurableDeliveryAdmissionV3 {
    /// Custody-only transfer. The fresh Host preview Read and later intake
    /// observer remain independently required; the old V3 Read is not renewed.
    pub fn prepare_retained_financial_result_v1(
        self,
        socket: &Path,
        request: &FinancialResultRequestV1,
        history: &AuthenticatedFinancialContinuationHistoryV1,
        original_host_material_delivery_ceiling: Instant,
        original: Box<dyn FinancialResultRestrictionV1>,
        preview_read: &dyn FinancialResultRestrictionV1,
    ) -> Result<PreparedFinancialResultReceiverV1> {
        self.intent.validate()?;
        request.validate()?;
        let status = self.status.as_ref().ok_or(BridgeError::Permission)?;
        self.check_status(status)?;
        let audit = status.verified_audit()?;
        let record = history.continuation_record();
        record.validate_request(history.continuation_request(), history.disclosure())?;
        let terms = &record.terms;
        let original_digest = wholepact_authority::durable_financial_continuation_v1::original_delivery_request_digest_v1(&status.request)?;
        history.financial_continuation_online_permits_v1(&history.continuation_request().operation_id)?;
        let permit = history.reservation()?.ok_or(BridgeError::Missing)?;
        if terms.scope != audit.scope
            || terms.original_delivery_operation_id != status.request.operation_id
            || terms.original_delivery_request_digest != original_digest
            || terms.original_local_intent_digest != status.original_local_intent_digest
            || terms.original_recipient_intent_digest != self.intent.digest()?
            || terms.original_recipient_enrollment_ref != self.intent.original_enrollment_ref
            || terms.original_recipient_manifest_ref != self.intent.original_manifest_ref
            || terms.original_recipient_enrollment_ref != audit.original_enrollment_ref
            || terms.original_recipient_manifest_ref != audit.original_accepted_manifest_ref
            || !history.contains_head(&terms.original_delivery_committed_head)
            || request.account_id != self.intent.account_id
            || request.fixed != self.intent.fixed
            || request.authorization_id != terms.scope.authorization.authorization_id
            || request.original_consent_ref != permit.request.original_consent_ref
            || request.authorization_id != permit.request.authorization_id
            || request.account_id != permit.request.account_id
        { return Err(BridgeError::Binding); }
        // Only shorten a retained genuine Host ceiling. This is not the old V3
        // read deadline and is not described as the Signer's source Instant.
        let monotonic = Instant::now();
        let wall_floor_ms = u64::try_from(std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH)
            .map_err(|_| BridgeError::Permission)?.as_millis()).map_err(|_| BridgeError::Permission)?;
        // Ceiling conversion rounds wall time upward; millisecond truncation
        // must never lengthen the retained absolute monotonic restriction.
        let wall_ms = wall_floor_ms.checked_add(1).ok_or(BridgeError::Permission)?;
        let from = terms.valid_from_ms.max(terms.scope.authorization.valid_from_ms);
        let until = terms.valid_until_ms.min(terms.scope.authorization.valid_until_ms);
        if wall_floor_ms < from || wall_ms >= until { return Err(BridgeError::Permission); }
        let deadline = original_host_material_delivery_ceiling.min(monotonic
            .checked_add(Duration::from_millis(until - wall_ms)).ok_or(BridgeError::Permission)?);
        original.check_before_io()?;
        preview_read.check_before_io()?;
        let receiver = PreparedFinancialResultReceiverV1::prepare_retained_original_v3(
            self.origin.provider, self.origin.peer, socket, request, deadline, original, preview_read,
        )?;
        if receiver.preview().continuation_request() != history.continuation_request()
            || receiver.preview().continuation_record() != record
        { return Err(BridgeError::Binding); }
        Ok(receiver)
    }
}
