//! Closed historical DATA selection for coordinated financial continuation.
//! This never creates a native or coordinated recipient, grant, or live source.
//! The entire namespace is decoded strictly before choosing an explicit profile;
//! a failed decoder is never retried as another profile.
use super::*;
use durable_born_entry_v1::OriginalDeliveryProfileV1;
use wholepact_authority::{OwnerControlRequest, WitnessDisclosureDescriptor};

pub(super) enum OriginalDeliveryEvidenceV1 {
    Native(RetainedDurableDeliveryAdmissionIntentV3),
    #[cfg(all(target_os = "linux", feature = "coordinated-financial-workflow-v1"))]
    Coordinated(authority::durable_delivery_admission_intent_v3::coordinated_v1::RetainedCoordinatedAdmissionIntentV1),
}
macro_rules! getter {
    ($name:ident, $ty:ty) => {
        pub(super) fn $name(&self) -> $ty {
            match self {
                Self::Native(v) => v.$name(),
                #[cfg(all(target_os = "linux", feature = "coordinated-financial-workflow-v1"))]
                Self::Coordinated(v) => v.$name(),
            }
        }
    };
}
impl OriginalDeliveryEvidenceV1 {
    getter!(request, &OwnerControlRequest);
    getter!(disclosure, &WitnessDisclosureDescriptor);
    getter!(owner_certificate_digest, &str);
    getter!(enrollment_ref, &str);
    getter!(manifest_ref, &str);
    getter!(history_digest, Result<String>);
    getter!(recipient_intent_digest, Result<String>);
    pub(super) fn original_host_process_instance(&self) -> &str {
        match self {
            Self::Native(v) => &v.recipient_intent().authorized_host_process_instance,
            #[cfg(all(target_os = "linux", feature = "coordinated-financial-workflow-v1"))]
            Self::Coordinated(v) => &v.recipient_intent().authorized_host_process_instance,
        }
    }
}
pub(in crate::consent_journal) fn profile(c: &Connection) -> Result<OriginalDeliveryProfileV1> {
    let values = financial_admission_intents::read_all(c)?;
    if values.len() != 1 { return Err(JournalError::RecoveryRequired); }
    match &values[0] {
        financial_admission_intents::HistoricalFinancialAdmissionIntent::V3(_) => Ok(OriginalDeliveryProfileV1::NativeV3),
        #[cfg(all(target_os = "linux", feature = "coordinated-financial-workflow-v1"))]
        financial_admission_intents::HistoricalFinancialAdmissionIntent::CoordinatedV3(_) => Ok(OriginalDeliveryProfileV1::CoordinatedV3),
        _ => Err(JournalError::RecoveryRequired),
    }
}
pub(super) fn read(c: &Connection, authorization_id: &str) -> Result<Option<OriginalDeliveryEvidenceV1>> {
    match profile(c)? {
        OriginalDeliveryProfileV1::NativeV3 => Ok(authority::durable_delivery_admission_intent_v3::read(c, authorization_id)?.map(OriginalDeliveryEvidenceV1::Native)),
        #[cfg(all(target_os = "linux", feature = "coordinated-financial-workflow-v1"))]
        OriginalDeliveryProfileV1::CoordinatedV3 => Ok(authority::durable_delivery_admission_intent_v3::coordinated_v1::read(c, authorization_id)?.map(OriginalDeliveryEvidenceV1::Coordinated)),
    }
}
pub(in crate::consent_journal) fn validate(c: &Connection, genesis: &AccountUseGenesis, limits: (u64,u64)) -> Result<()> {
    match profile(c)? {
        OriginalDeliveryProfileV1::NativeV3 => durable_born_entry_v1::validate_delivery_v3(c,genesis,limits),
        #[cfg(all(target_os = "linux", feature = "coordinated-financial-workflow-v1"))]
        OriginalDeliveryProfileV1::CoordinatedV3 => durable_born_entry_v1::validate_coordinated_delivery_v1(c,genesis,limits),
    }
}
pub(super) fn validate_cells(c: &Connection, genesis: &AccountUseGenesis, account: &SignerAccountState) -> Result<()> {
    match profile(c)? {
        OriginalDeliveryProfileV1::NativeV3 => durable_born_entry_v1::validate_delivery_v3_original_cells(c,genesis,account),
        #[cfg(all(target_os = "linux", feature = "coordinated-financial-workflow-v1"))]
        OriginalDeliveryProfileV1::CoordinatedV3 => durable_born_entry_v1::validate_coordinated_delivery_original_cells_v1(c,genesis,account),
    }
}
