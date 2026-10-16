//! Read-only owned selection and dedicated restriction append. Identifiers select
//! an existing enrolled row; supplied DTOs can never create this target.
use super::*;
use wholepact_signer_origin::manual_roster_v2::HostManualRosterEnrollmentRequestV2;
use wholepact_signer_origin::{
    PermanentStopLeaseV1, permanent_stop_v1::HostPermanentStopRequestV1,
};
use wholepact_store::manual_enrollment::{
    ManualEnrollmentAdditionalPublicationV3, ManualPermanentStopReceiptV1,
};

pub struct ManualPermanentStopTargetV1<'engine> {
    target: ManualEnrollmentTarget<'engine>,
    original: ManualEnrollmentAdditionalPublicationV3,
    request: HostPermanentStopRequestV1,
}
impl Engine {
    pub fn manual_permanent_stop_target_v1<'engine>(
        &'engine self,
        access: &Access,
        agreement_id: &str,
        account_id: &str,
    ) -> Result<ManualPermanentStopTargetV1<'engine>> {
        let selected = self.manual_enrollment_intent_target(access, agreement_id)?;
        let original = self
            .store
            .manual_permanent_stop_original_v1(&selected.store, &selected.record, account_id)
            .map_err(store_error)?;
        // This second actual Engine target verifies principal, network, obligation,
        // complete selected Access and the exact current agreement revision.
        let target = self.manual_enrollment_target_fail_fast(access, original.terms())?;
        let request = HostPermanentStopRequestV1 {
            version: 1,
            original: HostManualRosterEnrollmentRequestV2 {
                version: 2,
                enrollment: serde_json::from_value(
                    serde_json::to_value(&original.evidence.request.enrollment)
                        .map_err(|_| manual_denied())?,
                )
                .map_err(|_| manual_denied())?,
                roster: original.evidence.request.roster.clone(),
            },
            original_host_audit_digest: original.digest().map_err(store_error)?,
            provider_enrollment_ref: original.provider_enrollment_ref.clone(),
        };
        request.validate().map_err(|_| manual_denied())?;
        selected.check_current(access)?;
        target.check_current_fail_fast(access)?;
        Ok(ManualPermanentStopTargetV1 {
            target,
            original,
            request,
        })
    }
    /// Concrete live stop lease only; the Store atomically retains exclusion and
    /// original receipt provenance before returning the exact same-peer ack.
    pub fn append_manual_permanent_stop_v1(
        &self,
        access: &Access,
        target: &ManualPermanentStopTargetV1<'_>,
        lease: PermanentStopLeaseV1<'_>,
    ) -> Result<ManualPermanentStopReceiptV1> {
        if !std::ptr::eq(self, target.target.engine) || lease.evidence().request != target.request {
            return Err(manual_denied());
        }
        target.check_current(access)?;
        self.store
            .append_manual_permanent_stop_v1(
                &target.target.store,
                &target.target.agreement_record,
                lease,
            )
            .map_err(store_error)
    }
}
impl ManualPermanentStopTargetV1<'_> {
    pub fn terms(&self) -> &BornManualEnrollmentTerms {
        self.original.terms()
    }
    pub fn request(&self) -> &HostPermanentStopRequestV1 {
        &self.request
    }
    pub fn original(&self) -> &ManualEnrollmentAdditionalPublicationV3 {
        &self.original
    }
    pub fn store_destination_identity(&self) -> &str {
        self.target.store_destination_identity()
    }
    pub fn agreement_record_digest(&self) -> &str {
        self.target.agreement_record_digest()
    }
    pub fn check_current(&self, access: &Access) -> Result<()> {
        self.target.check_current_fail_fast(access)?;
        let actual = self
            .target
            .engine
            .store
            .manual_permanent_stop_original_v1(
                &self.target.store,
                &self.target.agreement_record,
                &self.terms().identity.account_id,
            )
            .map_err(store_error)?;
        if actual != self.original
            || self.request.original_host_audit_digest != actual.digest().map_err(store_error)?
            || self.request.provider_enrollment_ref != actual.provider_enrollment_ref
        {
            return Err(manual_denied());
        }
        Ok(())
    }
}
