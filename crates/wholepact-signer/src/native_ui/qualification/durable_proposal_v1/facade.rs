//! Opaque facade for the new profile. Only a genuinely retained born fixture can
//! open it. A public account ID, path, historic outbox or receipt cannot.
use super::*;
use crate::authority_bridge::{
    durable_construction_v1::{
        DurableConstructionCaptureRequestV1, DurableConstructionRedisclosureRequestV1,
        DurableConstructionRequestV1,
    },
    durable_review_ipc_v1::DurableReviewDeliveryRequestV1,
    preconstruction_ipc::PreconstructionRequest,
};
use crate::native_ui::runtime::durable_proposal_qualification_v1::DurableNativeFixtureV1;
pub use crate::native_ui::runtime::durable_proposal_qualification_v1::{
    DurableAdmissionCallFailureV1, DurableAdmissionCallbackStageV1, DurableAdmissionCompletionV1,
    DurableAdmissionDispatchFailureV1, DurableAdmissionDispatchMeasurementV1,
    DurableAdmissionDispatchStageV1, DurableAdmissionHistoryFailureV1,
    DurableAdmissionPreparationFailureV1, DurableAdmissionPreparationStageV1,
    DurableAdmissionRetentionV1, DurableNativeEntryFailureV1, DurableNativeEntryStageV1,
    DurableNativeRecordsV1,
};

pub use crate::authority_bridge::durable_flow_diagnostics_v1::{
    DurableFlowDiagnosticV1, DurableFlowFailureV1, DurableFlowObservationTokenV1,
    DurableFlowOperationV1, DurableFlowResultV1, DurableFlowStageV1, DurableFlowErrorV1,
    DurableFlowErrorDomainV1, DurableFlowErrorCodeV1, DurableFlowNestedCodeV1,
    DurableFlowCompletionV1, DurableFlowJobPurposeV1, DurableFlowReceiveV1,
    DurableFlowPresentationV1, DurableFlowCallOutcomesV1, DurableFlowCallOutcomeV1,
    DurableFlowTransportFailureV1, DurableFlowTransportPurposeV1, DurableFlowTransportStageV1,
    DurableFlowAuthorityCodeV1, DurableFlowCallbackStageV1,
};

pub struct EphemeralDurableNativeV1 {
    inner: DurableNativeFixtureV1,
}
impl EphemeralAcknowledgedBornV1 {
    /// This NEW focused entry authenticates the original born vault and journal.
    /// It does not carry a V3 construction owner or reuse any old native session.
    pub fn open_fresh_durable(
        self,
        proposal: wholepact_core::ProposalInput,
        aggregate_budget_zatoshis: u64,
    ) -> std::result::Result<EphemeralDurableNativeV1, DurableNativeEntryFailureV1> {
        Ok(EphemeralDurableNativeV1 {
            inner: DurableNativeFixtureV1::open(
                self.original,
                proposal,
                aggregate_budget_zatoshis,
            )?,
        })
    }
}
impl EphemeralDurableNativeV1 {
    pub fn endpoint(&self) -> Result<PathBuf> {
        self.inner.endpoint()
    }
    pub fn provider(&self) -> Result<InstalledSignerProvider> {
        self.inner.provider()
    }
    pub fn deadline(&self) -> Result<Instant> {
        self.inner.deadline()
    }
    pub fn scope(&self) -> &wholepact_signer_origin::PairScope {
        self.inner.scope()
    }
    pub fn native_entry_digest(&self) -> &str {
        self.inner.entry_digest()
    }
    pub fn poll_exact_pairing(&mut self) -> Result<bool> {
        self.inner.poll_pair()
    }
    pub fn accept_exact_manifest(&mut self) -> Result<DurableNativeRecordsV1> {
        self.inner.accept_exact_manifest()
    }
    pub fn original_records(&self) -> Result<DurableNativeRecordsV1> {
        self.inner.records()
    }
    pub fn expect_initial_disclosure(&mut self, request: PreconstructionRequest) -> Result<()> {
        self.inner.expect_initial_disclosure(request)
    }
    pub fn expect_durable_disclosure(
        &mut self,
        request: DurableConstructionRequestV1,
    ) -> Result<()> {
        self.inner.expect_durable_disclosure(request)
    }
    pub fn expect_durable_capture(
        &mut self,
        request: DurableConstructionCaptureRequestV1,
    ) -> Result<()> {
        self.inner.expect_durable_capture(request)
    }
    pub fn expect_redisclosure(
        &mut self,
        request: DurableConstructionRedisclosureRequestV1,
    ) -> Result<()> {
        self.inner.expect_redisclosure(request)
    }
    pub fn poll_exact_import(
        &mut self,
        request: &DurableReviewDeliveryRequestV1,
        identity: &wholepact_protocol::durable_proposal_v1::FixedProposalIdentityV1,
    ) -> Result<bool> {
        self.inner.poll_exact_import(request, identity)
    }
    pub fn poll_exact_disclosure(&mut self) -> Result<bool> {
        self.inner.poll_disclosure()
    }
    pub fn exact_durable_disclosure_committed(&self) -> Result<String> {
        self.inner.durable_disclosure_committed()
    }
    pub fn configure_native_wallet(&mut self, exact_setup_json: &str) -> Result<()> {
        self.inner.configure_wallet(exact_setup_json)
    }
    pub fn configure_durable_wallet(&mut self, exact_setup_json: &str) -> Result<()> {
        self.inner.configure_durable_wallet(exact_setup_json)
    }
    pub fn poll_financial_import(
        &mut self,
        request: &DurableReviewDeliveryRequestV1,
        identity: &wholepact_protocol::durable_proposal_v1::FixedProposalIdentityV1,
    ) -> Result<bool> {
        self.inner.poll_financial_import(request, identity)
    }
    pub fn sign_durable_fixed(
        &mut self,
        identity: &wholepact_protocol::durable_proposal_v1::FixedProposalIdentityV1,
    ) -> Result<(
        crate::authority_bridge::ipc::HistoryRequest,
        crate::authority_bridge::AuthorizationCommit,
    )> {
        self.inner.sign_durable_fixed(identity)
    }
    pub fn arm_financial_import_diagnostics(
        &mut self,
        request: &DurableReviewDeliveryRequestV1,
        identity: &wholepact_protocol::durable_proposal_v1::FixedProposalIdentityV1,
    ) -> DurableFlowObservationTokenV1 {
        self.inner
            .arm_financial_import_diagnostics(request, identity)
    }
    pub fn financial_import_deadline_diagnosed(
        &self,
        token: &DurableFlowObservationTokenV1,
    ) -> Result<Instant> {
        self.inner.financial_import_deadline_diagnosed(token)
    }
    pub fn poll_financial_import_diagnosed(
        &mut self,
        token: &DurableFlowObservationTokenV1,
        request: &DurableReviewDeliveryRequestV1,
        identity: &wholepact_protocol::durable_proposal_v1::FixedProposalIdentityV1,
    ) -> Result<bool> {
        self.inner
            .poll_financial_import_diagnosed(token, request, identity)
    }
    pub fn finish_financial_import_diagnostics(
        &mut self,
        token: DurableFlowObservationTokenV1,
        result: DurableFlowResultV1,
    ) -> Option<DurableFlowDiagnosticV1> {
        self.inner
            .finish_financial_import_diagnostics(token, result)
    }
    pub fn arm_result_service_diagnostics(&mut self) -> DurableFlowObservationTokenV1 {
        self.inner.arm_result_service_diagnostics()
    }
    pub fn result_service_deadline_diagnosed(
        &self,
        token: &DurableFlowObservationTokenV1,
    ) -> Result<Instant> {
        self.inner.result_service_deadline_diagnosed(token)
    }
    pub fn poll_result_service_diagnosed(
        &mut self,
        token: &DurableFlowObservationTokenV1,
    ) -> Result<()> {
        self.inner.poll_result_service_diagnosed(token)
    }
    pub fn finish_result_service_diagnostics(
        &mut self,
        token: DurableFlowObservationTokenV1,
        result: DurableFlowResultV1,
    ) -> Option<DurableFlowDiagnosticV1> {
        self.inner.finish_result_service_diagnostics(token, result)
    }
    pub fn reconcile_original_writer_diagnosed(
        &mut self,
    ) -> std::result::Result<(), DurableFlowFailureV1> {
        self.inner.reconcile_original_writer_diagnosed()
    }
    pub fn sign_durable_fixed_diagnosed(
        &mut self,
        identity: &wholepact_protocol::durable_proposal_v1::FixedProposalIdentityV1,
    ) -> std::result::Result<
        (
            crate::authority_bridge::ipc::HistoryRequest,
            crate::authority_bridge::AuthorizationCommit,
        ),
        DurableFlowFailureV1,
    > {
        self.inner.sign_durable_fixed_diagnosed(identity)
    }

    pub fn configure_original_witness(&mut self) -> Result<()> {
        self.inner.configure_original_witness()
    }
    /// Returns ordinary request data from the genuine pending native review.
    /// This neither approves nor retains the financial admission.
    pub fn prepare_durable_admission(
        &mut self,
    ) -> std::result::Result<
        wholepact_authority::OwnerControlRequest,
        DurableAdmissionPreparationFailureV1,
    > {
        self.inner.prepare_durable_admission()
    }
    /// Consumes the actual pending review through the production native route,
    /// which retains the immutable intent before its first mutation frame.
    pub fn approve_durable_admission(&mut self) -> Result<()> {
        self.inner.approve_durable_admission()
    }
    /// Optional inert evidence from the same native approval and worker. The
    /// operational result and existing completion requirements are unchanged.
    pub fn approve_durable_admission_diagnosed(
        &mut self,
    ) -> std::result::Result<(), DurableAdmissionDispatchFailureV1> {
        self.inner.approve_durable_admission_diagnosed()
    }
    pub fn reconcile_original_writer(&mut self) -> Result<()> {
        self.inner.reconcile_original_writer()
    }
    pub fn poll_data_only(&mut self) -> Result<()> {
        self.inner.poll_data_only()
    }
    /// Revokes and drains the actual runtime before giving back historical
    /// fixture custody. The caller must discard its old authenticated IPC client.
    pub fn close_original_entry(self) -> Result<EphemeralAcknowledgedBornV1> {
        Ok(EphemeralAcknowledgedBornV1 {
            original: self.inner.close()?,
        })
    }
}
