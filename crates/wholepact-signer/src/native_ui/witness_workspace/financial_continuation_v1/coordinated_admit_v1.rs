//! One exact retained owner-mTLS admission in the coordinated workflow.
//! No client/key escape, Native action conversion, retry, source replacement
//! or writer credential opening.
use super::*;
use crate::account::birth::enrollment::roster_v2::financial_source_v1::FinancialAdmissionSourcePinV1;
use crate::native_peer::PeerProcess;
use wholepact_financial_coordinator_origin::{SignerAdmitArmV1, SignerAdmitFinalV1};

/// Consumed-attempt classification only. No failure returns Pending, a pin or
/// Final. Entering checked transport is conservatively uncertain even if its
/// own first restriction sample failed before a physical attempt was observed.
#[derive(Debug)]
pub(in crate::native_ui) struct CoordinatedAdmitFailureV1 {
    cause: Error,
    transport_entered: bool,
}
impl CoordinatedAdmitFailureV1 {
    pub(in crate::native_ui) fn before_transport(cause: Error) -> Self {
        Self {
            cause,
            transport_entered: false,
        }
    }
    pub(in crate::native_ui) fn after_transport(cause: Error) -> Self {
        Self {
            cause,
            transport_entered: true,
        }
    }
    pub(in crate::native_ui) fn cause(&self) -> &Error {
        &self.cause
    }
    pub(in crate::native_ui) fn is_uncertain(&self) -> bool {
        self.transport_entered
    }
}

impl FinancialWitnessCustodyV1 {
    pub(in crate::native_ui) fn prepare_coordinated_admit_pin_v1(
        &self,
        source: &PreparedOriginalFinancialSourceV1,
        pending: &PendingFinancialContinuationAdmissionV1,
        host: &PeerProcess,
        arm: &SignerAdmitArmV1,
    ) -> Result<FinancialAdmissionSourcePinV1> {
        arm.check_current()?;
        if !self.owner {
            return Err(Error::Authentication);
        }
        let pin = source.prepare_coordinated_admission_source_pin_v1(
            pending,
            &self.client.disclosure_descriptor(),
            &self.certificate_digest,
            host,
            arm,
        )?;
        arm.check_current()?;
        Ok(pin)
    }

    pub(in crate::native_ui) fn admit_coordinated_once_v1(
        &self,
        source: &PreparedOriginalFinancialSourceV1,
        pending: PendingFinancialContinuationAdmissionV1,
        pin: FinancialAdmissionSourcePinV1,
        host: &PeerProcess,
        final_action: SignerAdmitFinalV1,
    ) -> std::result::Result<AccountSnapshot, CoordinatedAdmitFailureV1> {
        type Failure = CoordinatedAdmitFailureV1;
        final_action
            .check_current()
            .map_err(|e| Failure::before_transport(e.into()))?;
        if !self.owner {
            return Err(Failure::before_transport(Error::Authentication));
        }
        let disclosure = self.client.disclosure_descriptor();
        let check = || -> Result<()> {
            final_action.check_current()?;
            source.check_coordinated_admission_source_pin_v1(
                &pin,
                &pending,
                &disclosure,
                &self.certificate_digest,
                host,
                &final_action,
            )?;
            final_action.check_current()?;
            Ok(())
        };
        check().map_err(Failure::before_transport)?;
        // This is the same actual owner client opened under initial Read and
        // retained through Continue. Its new_restricted_v1 observer checks the
        // original shared R at each physical I/O attempt, independently of this
        // concrete action/source callback. No unrestricted fallback exists here.
        let deadline = final_action
            .original_admit_deadline()
            .min(source.original_deadline());
        let result = self.client.admit_financial_continuation_v1_checked_until(
            pending.request(),
            deadline,
            || check().map_err(|_| wholepact_authority::AuthorityError::Permission),
        );
        // The checked transport validates the exact request and authenticated
        // committed head. Any later error, including R/death/expiry or reporting
        // loss, must not turn a possibly committed request into a retry ticket.
        let current = check();
        drop(final_action);
        drop(pending);
        drop(pin);
        current.map_err(Failure::after_transport)?;
        result.map_err(|_| Failure::after_transport(Error::Uncertain))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn coordinated_admit_transport_classification_is_monotone() {
        let before = CoordinatedAdmitFailureV1::before_transport(Error::ReviewMismatch);
        assert!(!before.is_uncertain());
        let after = CoordinatedAdmitFailureV1::after_transport(Error::Locked);
        assert!(after.is_uncertain());
        assert!(matches!(after.cause(), Error::Locked));
    }
}
