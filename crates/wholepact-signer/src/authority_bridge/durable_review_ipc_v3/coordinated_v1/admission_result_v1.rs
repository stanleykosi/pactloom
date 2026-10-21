//! Consumes the actual verified original V3 owner, not a peer/provider factory.
use super::*;
use crate::authority_bridge::durable_delivery_admission_ipc_v3::{
    RetainedFinancialResultJoinV1, checked_retained_result_deadline_v1,
};
use crate::authority_bridge::financial_continuation_v1::{
    AuthenticatedFinancialContinuationHistoryV1, FinancialResultRequestV1,
    FinancialResultRestrictionV1, PreparedCoordinatedFinancialResultReceiverV1,
};
use std::path::Path;
impl PendingCoordinatedDurableDeliveryAdmissionV1 {
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
    ) -> Result<PreparedCoordinatedFinancialResultReceiverV1> {
        self.intent.validate()?;
        request.validate()?;
        let status = self.status.as_ref().ok_or(BridgeError::Permission)?;
        self.check_status(status)?;
        let audit = status.verified_audit()?;
        let intent_digest = self.intent.digest()?;
        let deadline = checked_retained_result_deadline_v1(
            RetainedFinancialResultJoinV1 {
                intent_digest: &intent_digest,
                account_id: &self.intent.account_id,
                fixed: &self.intent.fixed,
                original_enrollment_ref: &self.intent.original_enrollment_ref,
                original_manifest_ref: &self.intent.original_manifest_ref,
                admission_request: &status.request,
                original_local_intent_digest: &status.original_local_intent_digest,
                audit,
            },
            request,
            history,
            original_host_material_delivery_ceiling,
        )?;
        let record = history.continuation_record();
        original.check_before_io()?;
        preview_read.check_before_io()?;
        let receiver =
            PreparedCoordinatedFinancialResultReceiverV1::prepare_retained_coordinated_v1(
                self.client,
                socket,
                request,
                deadline,
                original,
                preview_read,
            )?;
        if receiver.preview().continuation_request() != history.continuation_request()
            || receiver.preview().continuation_record() != record
        {
            return Err(BridgeError::Binding);
        }
        Ok(receiver)
    }
}
