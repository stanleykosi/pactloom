//! One READY attempt under its distinct genuine conditional Arm.
use super::*;
use wholepact_financial_coordinator_origin::SignerV3AdmitArmV1;

impl CoordinatedDeliveryWitnessV1 {
    pub(in crate::native_ui) fn prepare_admission(
        &self,
        arm: &SignerV3AdmitArmV1,
        request: &OwnerControlRequest,
        mut check_source: impl FnMut() -> Result<()>,
    ) -> Result<AuthenticatedDurableAdmissionChannelV3<'_>> {
        let check = || -> Result<()> {
            self.check_custody()?;
            arm.check_current()?;
            arm.presentation().validate()?;
            let facts = arm.facts();
            if facts.read.source_identity_digest != self.opened.source_identity
                || facts.read.owner_service_digest != self.opened.owner_service_digest
                || facts.request_json
                    != serde_json::to_string(request).map_err(|_| Error::InvalidData)?
                || facts.read.admission_request_digest
                    != wholepact_core::proposal::canonical_digest(
                        "wholepact:coordinated-durable-delivery-admission-request:v1",
                        request,
                    )
                    .map_err(|_| Error::InvalidData)?
                || arm.original_source_deadline() != self.opened.original_source_deadline
                || arm.original_service_deadline() != self.opened.original_service_deadline
            {
                return Err(Error::ReviewMismatch);
            }
            Ok(())
        };
        check()?;
        check_source()?;
        let mut callback_error = None;
        let result = self.opened.client.prepare_durable_delivery_admission_v3(
            request,
            arm.original_admit_deadline(),
            || {
                check().and_then(|_| check_source()).map_err(|error| {
                    if callback_error.is_none() {
                        callback_error = Some(error);
                    }
                    wholepact_authority::AuthorityError::Permission
                })
            },
        );
        if let Some(error) = callback_error {
            return Err(error);
        }
        // Never auto-retry, including a refusal before READY. This owner has one
        // original conditional attempt and never creates a replacement deadline.
        let channel = result.map_err(|_| Error::Uncertain)?;
        check()?;
        check_source()?;
        channel.check_current().map_err(|_| Error::Uncertain)?;
        Ok(channel)
    }
}
