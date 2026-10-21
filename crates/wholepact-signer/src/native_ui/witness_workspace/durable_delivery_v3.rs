//! Closed custody of already reviewed original owner credentials. This owner
//! cannot enter ordinary Witness, writer, reservation or financial routes.
use super::*;
#[cfg(feature = "coordinated-financial-workflow-v1")]
#[path = "durable_delivery_v3/coordinated_v1.rs"]
pub(in crate::native_ui) mod coordinated_v1;
use crate::native_ui::PreparedReceiveAndViewAuthorityV3;
use std::{sync::Arc, time::Instant};
use wholepact_authority::{OwnerControlRequest, ReconciledAuthorityHistory};
use wholepact_authority::transport::{AuthenticatedDurableAdmissionChannelV3, durable_delivery_admission_v3::PrepareDurableAdmissionErrorV3};

pub(in crate::native_ui) struct PreparedDeliveryWitnessV3 {
    client: AuthorityClient,
    account_id: String,
    certificate_digest: String,
}
impl NativeWitnessWorkspace {
    pub(in crate::native_ui) fn into_prepared_delivery_v3(
        self, origin: &NativeAuthorityBinding, disclosure: &WitnessDisclosureDescriptor,
        certificate: &str,
    ) -> Result<PreparedDeliveryWitnessV3> {
        self.require_durable_credential_v1(origin, disclosure, certificate)?;
        let Self { instance: _, source: _, account_id, client, writer_certificate_digest } = self;
        Ok(PreparedDeliveryWitnessV3 {client, account_id, certificate_digest:writer_certificate_digest})
    }
}
impl PreparedDeliveryWitnessV3 {
    pub(in crate::native_ui) fn prepare_history(json: &str, disclosure: &WitnessDisclosureDescriptor, certificate: &str) -> Result<Self> {
        let selected = prepare_selected_witness_configuration(json, &disclosure.account_id, None)?;
        if selected.client.disclosure_descriptor() != *disclosure || selected.writer_certificate_digest != certificate {return Err(Error::Authentication);}
        Ok(Self {client:selected.client, account_id:selected.account_id, certificate_digest:selected.writer_certificate_digest})
    }

    pub(in crate::native_ui) fn activate(self, read: Arc<PreparedReceiveAndViewAuthorityV3>, source_identity: &str) -> Result<DeliveryWitnessV3> {
        read.check_source(source_identity)?;
        Ok(DeliveryWitnessV3 {prepared:self, read, source_identity:source_identity.into()})
    }
}
pub(in crate::native_ui) struct DeliveryWitnessV3 {
    prepared: PreparedDeliveryWitnessV3,
    read: Arc<PreparedReceiveAndViewAuthorityV3>,
    source_identity: String,
}
#[derive(Clone,Copy)]
pub(in crate::native_ui) enum HistoryReadPurposeV3 { PrepareAdmission, ReadOriginalHistory }
impl DeliveryWitnessV3 {
    pub(in crate::native_ui) fn into_history_preparation(self) -> PreparedDeliveryWitnessV3 { self.prepared }
    pub(in crate::native_ui) fn check_current(&self) -> Result<()> { self.read.check_source(&self.source_identity) }
    pub(in crate::native_ui) fn require_original(&self, disclosure:&WitnessDisclosureDescriptor, certificate:&str) -> Result<()> {
        self.check_current()?;
        if self.prepared.client.disclosure_descriptor() != *disclosure || self.prepared.account_id != disclosure.account_id || self.prepared.certificate_digest != certificate {return Err(Error::Authentication);}
        Ok(())
    }
    pub(in crate::native_ui) fn history(&self, purpose:HistoryReadPurposeV3, deadline:Instant, mut check:impl FnMut()->Result<()>) -> Result<ReconciledAuthorityHistory> {
        self.check_current()?;
        #[cfg(feature="synthetic-born-joined-qualification")]
        let stage=match purpose {
            HistoryReadPurposeV3::PrepareAdmission=>crate::native_ui::runtime::delivery_diagnostics_v2::Stage::DeliveryNativeAdmission,
            HistoryReadPurposeV3::ReadOriginalHistory=>crate::native_ui::runtime::delivery_diagnostics_v2::Stage::DeliveryHistoricalRead,
        };
        #[cfg(not(feature="synthetic-born-joined-qualification"))]
        let _=purpose;
        let mut callback_error = None;
        let result = self.prepared.client.reconcile_history_checked_until(deadline, || {
            self.check_current().and_then(|_|check()).map_err(|error| {
                #[cfg(feature="synthetic-born-joined-qualification")]
                crate::native_ui::runtime::delivery_diagnostics_v2::signer_failure(stage,&error);
                if callback_error.is_none() {callback_error=Some(error);}
                wholepact_authority::AuthorityError::Permission
            })
        });
        if let Some(error)=callback_error {return Err(error);}
        let history=result.map_err(|error| {
            #[cfg(feature="synthetic-born-joined-qualification")]
            crate::native_ui::runtime::delivery_diagnostics_v2::bridge_failure(stage,&crate::authority_bridge::BridgeError::Authority(error));
            #[cfg(not(feature="synthetic-born-joined-qualification"))]
            let _=error;
            Error::Uncertain
        })?;
        self.check_current()?; check()?;
        if history.disclosure() != &self.prepared.client.disclosure_descriptor() {return Err(Error::Authentication);}
        Ok(history)
    }
    pub(in crate::native_ui) fn prepare_admission(
        &self, request:&OwnerControlRequest, deadline:Instant, mut check:impl FnMut()->Result<()>,
    ) -> std::result::Result<AuthenticatedDurableAdmissionChannelV3<'_>, PrepareDurableAdmissionErrorV3> {
        self.prepared.client.prepare_durable_delivery_admission_v3(request, deadline, || {
            self.check_current().and_then(|_|check()).map_err(|_|wholepact_authority::AuthorityError::Permission)
        })
    }
}
