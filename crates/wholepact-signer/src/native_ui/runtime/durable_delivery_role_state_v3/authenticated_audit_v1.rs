//! Shared historical equality kernel, not an Audit permission or completion
//! constructor. Callers must obtain the complete history with their own nominal
//! read grant and join their actual retained local record and original receipt.
//! Neither a status DTO nor a phase flag can stand in for that custody.
use crate::{Error, Result};
use wholepact_authority::{
    AccountSnapshot, OwnerControlRequest, ReconciledAuthorityHistory, WitnessDisclosureDescriptor,
};

/// Keep the maintained native audit's lookup, equality order and conservative
/// error classification. A lost response may omit `controlled`; it never
/// relaxes the requirement for the exact committed request in complete history.
/// Success is only data validation, never evidence of current material or a
/// newly issued read, action, SourceEntry or financial capability.
pub(in crate::native_ui::runtime) fn require_exact_original(
    history: &ReconciledAuthorityHistory,
    request: &OwnerControlRequest,
    disclosure: &WitnessDisclosureDescriptor,
    owner_certificate_digest: &str,
    controlled: Option<&AccountSnapshot>,
) -> Result<()> {
    let remote = history
        .durable_delivery_admission_v2(&request.operation_id)
        .map_err(|_| Error::RecoveryRequired)?;
    if remote != Some(request)
        || history.disclosure() != disclosure
        || history.account_policy().owner_certificate_digest != owner_certificate_digest
    {
        return Err(Error::Uncertain);
    }
    if controlled.is_some_and(|snapshot| snapshot != history.snapshot()) {
        return Err(Error::Uncertain);
    }
    Ok(())
}
