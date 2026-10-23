//! Engine-owned read of an exact additional-account roster predecessor. This
//! object selects current metadata only; it cannot authorize a publication.
use super::*;
use wholepact_core::manual_roster_v2::HostRosterAppendBindingV2;
use wholepact_store::manual_enrollment::ManualEnrollmentRosterHead;

pub struct ManualRosterIntentTarget<'engine> {
    intent: ManualEnrollmentIntentTarget<'engine>,
    head: ManualEnrollmentRosterHead<'engine>,
}
/// Private lexical source read, never retained across permission callbacks.
pub(crate) struct OriginalManualRosterSourceReadV3<'target, 'engine> {
    target: &'target ManualRosterIntentTarget<'engine>,
    read: wholepact_store::manual_enrollment::OriginalManualRosterReadV3<'target, 'engine>,
}
impl OriginalManualRosterSourceReadV3<'_, '_> {
    pub(crate) fn check_current(&self, access: &Access) -> Result<()> {
        self.target.intent.check_current(access)?;
        self.read.check_current_v3().map_err(store_error)
    }
    pub(crate) fn members(
        &self,
        access: &Access,
    ) -> Result<&[wholepact_store::manual_enrollment::ManualEnrollmentRosterMember]> {
        self.check_current(access)?;
        let members = self.read.members_v3().map_err(store_error)?;
        for member in members {
            let record = self.target.intent.store
                .current_agreement_record(&member.scope.agreement_id)
                .map_err(store_error)?;
            let envelope = decode(&record)?;
            if !access.permits_agreement(&record.id, &envelope.owner_client_id) {
                return Err(manual_denied());
            }
        }
        self.check_current(access)?;
        Ok(members)
    }
}
impl Engine {
    pub fn manual_roster_intent_target<'engine>(
        &'engine self,
        access: &Access,
        agreement_id: &str,
    ) -> Result<ManualRosterIntentTarget<'engine>> {
        let intent = self.manual_enrollment_intent_target(access, agreement_id)?;
        let head = self
            .store
            .manual_enrollment_roster_head(&intent.store, &intent.record)
            .map_err(store_error)?;
        intent.check_current(access)?;
        head.check_current().map_err(store_error)?;
        Ok(ManualRosterIntentTarget { intent, head })
    }
}
impl ManualRosterIntentTarget<'_> {
    pub fn members(
        &self,
        access: &Access,
    ) -> Result<&[wholepact_store::manual_enrollment::ManualEnrollmentRosterMember]> {
        self.check_current(access)?;
        let members = self.head.members().map_err(store_error)?;
        for member in members {
            let record = self
                .intent
                .store
                .current_agreement_record(&member.scope.agreement_id)
                .map_err(store_error)?;
            let envelope = decode(&record)?;
            if !access.permits_agreement(&record.id, &envelope.owner_client_id) {
                return Err(manual_denied());
            }
        }
        self.check_current(access)?;
        Ok(members)
    }
    pub fn binding(&self) -> &HostRosterAppendBindingV2 {
        self.head.binding()
    }
    pub fn agreement(&self) -> &wholepact_core::AgreementDraft {
        self.intent.agreement()
    }
    pub fn principal_id(&self) -> &str {
        self.intent.principal_id()
    }
    pub fn owner_client_id(&self) -> &str {
        self.intent.owner_client_id()
    }
    pub fn generation_id(&self) -> &str {
        self.intent.generation_id()
    }
    pub fn inventory_digest(&self) -> &str {
        self.intent.inventory_digest()
    }
    pub fn store_destination_identity(&self) -> &str {
        self.intent.store_destination_identity()
    }
    pub fn check_current(&self, access: &Access) -> Result<()> {
        self.intent.check_current(access)?;
        self.head.check_current().map_err(store_error)
    }
}
impl<'engine> ManualRosterIntentTarget<'engine> {
    pub(crate) fn original_source_read_v3(
        &self,
        access: &Access,
    ) -> Result<OriginalManualRosterSourceReadV3<'_, 'engine>> {
        // Preserve the original intent/access check BEFORE the full head read.
        self.intent.check_current(access)?;
        let read = self.head.original_read_v3().map_err(store_error)?;
        Ok(OriginalManualRosterSourceReadV3 { target: self, read })
    }
}

impl Engine {
    #[allow(clippy::too_many_arguments)]
    pub fn manual_roster_request_original(
        &self,
        access: &Access,
        target: &ManualEnrollmentTarget<'_>,
        request: &wholepact_signer_origin::manual_roster_v2::HostManualRosterPublicationRequestV2,
        enrollment_ref: &str,
        witness_extension_digest: &str,
        witness_roster_extension_digest: &str,
        signer_roster_record_digest: &str,
    ) -> Result<Option<wholepact_store::manual_enrollment::ManualEnrollmentAdditionalPublicationV3>>
    {
        if !std::ptr::eq(self, target.engine) || request.enrollment.terms != target.terms {
            return Err(manual_denied());
        }
        target.check_current(access)?;
        self.store
            .manual_enrollment_roster_request_original(
                &target.store,
                &target.agreement_record,
                request,
                enrollment_ref,
                witness_extension_digest,
                witness_roster_extension_digest,
                signer_roster_record_digest,
            )
            .map_err(store_error)
    }
    pub fn append_manual_roster_initial_v3(
        &self,
        access: &Access,
        target: &ManualEnrollmentTarget<'_>,
        idempotency_key: &str,
        lease: wholepact_signer_origin::ManualRosterEnrollmentLeaseV2<'_>,
    ) -> Result<wholepact_store::manual_enrollment::ManualAuditAppendReceipt> {
        if !std::ptr::eq(self, target.engine) || lease.binding().enrollment.terms != target.terms {
            return Err(manual_denied());
        }
        target.check_current(access)?;
        let context = wholepact_store::CommandContext::for_request(
            &access.principal_id,
            idempotency_key,
            &serde_json::to_value(lease.binding()).map_err(|_| manual_denied())?,
        )
        .map_err(store_error)?;
        self.store
            .append_manual_enrollment_additional_publication_v3(
                &target.store,
                &context,
                &target.agreement_record,
                lease,
            )
            .map_err(store_error)
    }
    pub fn append_manual_roster_continuation_v4(
        &self,
        access: &Access,
        target: &ManualEnrollmentTarget<'_>,
        idempotency_key: &str,
        lease: wholepact_signer_origin::ManualRosterEnrollmentLeaseV2<'_>,
    ) -> Result<wholepact_store::manual_enrollment::ManualAuditAppendReceipt> {
        if !std::ptr::eq(self, target.engine) || lease.binding().enrollment.terms != target.terms {
            return Err(manual_denied());
        }
        target.check_current(access)?;
        let context = wholepact_store::CommandContext::for_request(
            &access.principal_id,
            idempotency_key,
            &serde_json::to_value(lease.binding()).map_err(|_| manual_denied())?,
        )
        .map_err(store_error)?;
        self.store
            .append_manual_enrollment_continuation_audit_v4(
                &target.store,
                &context,
                &target.agreement_record,
                lease,
            )
            .map_err(store_error)
    }
}
