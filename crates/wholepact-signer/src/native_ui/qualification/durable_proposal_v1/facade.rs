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
use crate::native_ui::runtime::durable_proposal_qualification_v1::{
    DurableDisclosureWaitV1, DurableFinancialImportWaitV1, DurableNativeFixtureV1,
};
pub use crate::native_ui::runtime::durable_proposal_qualification_v1::{
    DurableAdmissionCallFailureV1, DurableAdmissionCallbackStageV1, DurableAdmissionCompletionV1,
    DurableAdmissionDispatchFailureV1, DurableAdmissionDispatchMeasurementV1,
    DurableAdmissionDispatchStageV1, DurableAdmissionHistoryFailureV1,
    DurableAdmissionPreparationFailureV1, DurableAdmissionPreparationStageV1,
    DurableAdmissionRetentionV1, DurableNativeEntryFailureV1, DurableNativeEntryStageV1,
    DurableNativeRecordsV1, DurableAcquireReplyLossV1,
};

pub use crate::authority_bridge::durable_flow_diagnostics_v1::{
    DurableFlowAfterDrainV1, DurableFlowAuthorityCodeV1, DurableFlowCallOutcomeV1,
    DurableFlowCallOutcomesV1, DurableFlowCallbackStageV1, DurableFlowCompletionV1,
    DurableFlowDiagnosticV1, DurableFlowErrorCodeV1, DurableFlowErrorDomainV1, DurableFlowErrorV1,
    DurableFlowFailureV1, DurableFlowJobPurposeV1, DurableFlowNestedCodeV1,
    DurableFlowObservationTokenV1, DurableFlowOperationV1, DurableFlowPresentationV1,
    DurableFlowReceiveV1, DurableFlowResultV1, DurableFlowStageV1, DurableFlowTransportFailureV1,
    DurableFlowTransportPurposeV1, DurableFlowTransportStageV1, DurableLifecycleDiagnosticV1,
    DurableLifecyclePointV1, DurableLifecyclePointMeasurementV1, DurablePendingWaitKindV1,
    DurablePendingWaitCostV1,
};

pub struct EphemeralDurableNativeV1 {
    inner: DurableNativeFixtureV1,
}
/// One fixed synthetic import wait. Exclusive borrowing prevents interleaving
/// another request or operation; dropping the waiter makes no success claim.
pub struct EphemeralDurableFinancialImportWaitV1<'a> {
    inner: DurableFinancialImportWaitV1<'a>,
}
impl EphemeralDurableFinancialImportWaitV1<'_> {
    pub fn deadline(&self) -> Instant {
        self.inner.deadline()
    }
    pub fn poll(&mut self) -> Result<bool> {
        self.inner.poll()
    }
}
/// One fixed paired disclosure wait, never a reusable validation or approval.
pub struct EphemeralDurableDisclosureWaitV1<'a> {
    inner: DurableDisclosureWaitV1<'a>,
}
impl EphemeralDurableDisclosureWaitV1<'_> {
    pub fn deadline(&self) -> Instant {
        self.inner.deadline()
    }
    pub fn poll(&mut self) -> Result<bool> {
        self.inner.poll()
    }
}
impl EphemeralAcknowledgedBornV1 {
    /// The same genuine opener, with opt-in inert owner-lifetime evidence only.
    pub fn open_fresh_durable_diagnosed(
        self,
        proposal: wholepact_core::ProposalInput,
        aggregate_budget_zatoshis: u64,
    ) -> std::result::Result<EphemeralDurableNativeV1, DurableNativeEntryFailureV1> {
        Ok(EphemeralDurableNativeV1 {
            inner: DurableNativeFixtureV1::open_diagnosed(
                self.original,
                proposal,
                aggregate_budget_zatoshis,
            )?,
        })
    }
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
    pub fn begin_financial_import_wait_diagnosed<'a>(
        &'a mut self,
        token: &'a DurableFlowObservationTokenV1,
        request: &'a DurableReviewDeliveryRequestV1,
        identity: &'a wholepact_protocol::durable_proposal_v1::FixedProposalIdentityV1,
    ) -> Result<EphemeralDurableFinancialImportWaitV1<'a>> {
        Ok(EphemeralDurableFinancialImportWaitV1 {
            inner: self
                .inner
                .begin_financial_import_wait_diagnosed(token, request, identity)?,
        })
    }
    pub fn begin_disclosure_wait(&mut self) -> Result<EphemeralDurableDisclosureWaitV1<'_>> {
        Ok(EphemeralDurableDisclosureWaitV1 {
            inner: self.inner.begin_disclosure_wait()?,
        })
    }
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
    pub fn acquire_original_writer_expecting_reply_loss_diagnosed(
        &mut self,
    ) -> std::result::Result<DurableAcquireReplyLossV1, DurableFlowFailureV1> {
        self.inner
            .acquire_original_writer_expecting_reply_loss_diagnosed()
    }
    pub fn retry_original_writer_after_reply_loss_diagnosed(
        &mut self,
    ) -> std::result::Result<wholepact_authority::WriterSessionReceipt, DurableFlowFailureV1> {
        self.inner
            .retry_original_writer_after_reply_loss_diagnosed()
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
    /// Read authenticated complete history after a genuine fresh native entry
    /// and reimport. The expected original request supplies correlation only;
    /// no admission, approval, writer session or deadline is renewed.
    pub fn observe_committed_durable_admission(
        &mut self,
        expected: &wholepact_authority::OwnerControlRequest,
    ) -> std::result::Result<(), DurableAdmissionPreparationFailureV1> {
        self.inner.observe_committed_durable_admission(expected)
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

pub use crate::native_ui::runtime::durable_proposal_qualification_v1::{
    DurableDeliveryFailureV2, DurableDeliveryStageV2,
};
pub struct EphemeralDurableDeliveryNativeV2 {
    inner:crate::native_ui::runtime::durable_proposal_qualification_v1::DurableDeliveryNativeFixtureV2,
}
/// Exclusive borrowed wait for one exact import into the actual v2 entry.
/// A completed wait grants no admission, writer, signing or reuse authority.
pub struct EphemeralDurableDeliveryImportWaitV2<'a> {
    inner:
        crate::native_ui::runtime::durable_proposal_qualification_v1::DurableDeliveryImportWaitV2<
            'a,
        >,
}
impl EphemeralDurableDeliveryImportWaitV2<'_> {
    pub fn deadline(&self) -> Instant {
        self.inner.deadline()
    }
    pub fn poll(&mut self) -> Result<bool> {
        self.inner.poll()
    }
    /// Takes only this attempt's actual owned failure, even after liveness ends.
    /// A queued success remains behind all original runtime adoption checks.
    pub fn take_failure(&mut self) -> Option<DurableDeliveryFailureV2> {
        self.inner.take_failure()
    }
}
impl EphemeralAcknowledgedBornV1 {
    pub fn open_fresh_durable_delivery_v2(
        self,
        proposal: wholepact_core::ProposalInput,
        aggregate_budget_zatoshis: u64,
    ) -> std::result::Result<EphemeralDurableDeliveryNativeV2, DurableNativeEntryFailureV1> {
        Ok(EphemeralDurableDeliveryNativeV2{inner:crate::native_ui::runtime::durable_proposal_qualification_v1::DurableDeliveryNativeFixtureV2::open(self.original,proposal,aggregate_budget_zatoshis)?})
    }
}
impl EphemeralDurableDeliveryNativeV2 {
    /// Diagnostic-only drain of an already accepted exact import's queued Err.
    /// No job is started and queued Ok is left for the original adoption gates.
    pub fn drain_import_failure_before_wait(
        &mut self,
        request: &DurableReviewDeliveryRequestV1,
    ) -> Option<DurableDeliveryFailureV2> {
        self.inner.drain_import_failure_before_wait(request)
    }
    pub fn begin_import_wait<'a>(
        &'a mut self,
        request: &'a DurableReviewDeliveryRequestV1,
        identity: &'a wholepact_protocol::durable_proposal_v1::FixedProposalIdentityV1,
    ) -> Result<EphemeralDurableDeliveryImportWaitV2<'a>> {
        Ok(EphemeralDurableDeliveryImportWaitV2 {
            inner: self.inner.begin_import_wait(request, identity)?,
        })
    }
    /// Synthetic-only same-original process reentry. Paths/config are inert
    /// inputs: the actual production source opener and native owner reverify
    /// the original encrypted files. No acknowledged fixture is reconstructed.
    pub fn open_existing_durable_delivery_v2(
        root: PathBuf,
        proposal: wholepact_core::ProposalInput,
        aggregate_budget_zatoshis: u64,
        owner_setup_json: String,
    ) -> std::result::Result<Self, DurableNativeEntryFailureV1> {
        Ok(Self{inner:crate::native_ui::runtime::durable_proposal_qualification_v1::DurableDeliveryNativeFixtureV2::open_existing(root,proposal,aggregate_budget_zatoshis,owner_setup_json)?})
    }
    pub fn endpoint(&self) -> Result<PathBuf> {
        self.inner.endpoint()
    }
    pub fn provider(&self) -> Result<InstalledSignerProvider> {
        self.inner.provider()
    }
    pub fn scope(&self) -> &wholepact_signer_origin::PairScope {
        self.inner.scope()
    }
    pub fn deadline(&self) -> Result<Instant> {
        self.inner.deadline()
    }
    pub fn native_entry_digest(&self) -> &str {
        self.inner.entry_digest()
    }
    pub fn original_root(&self) -> Result<PathBuf> {
        self.inner.original_root()
    }
    pub fn coordinated_pre_v3_metadata(&self) -> Result<String> {
        self.inner.coordinated_pre_v3_metadata()
    }
    pub fn owner_configuration_for_reopen(&self) -> Result<String> {
        self.inner.owner_setup_for_reopen()
    }
    pub fn poll_exact_pairing(&mut self) -> Result<bool> {
        self.inner.poll_pair()
    }
    pub fn accept_exact_manifest(&mut self) -> Result<DurableNativeRecordsV1> {
        self.inner.accept_exact_manifest()
    }
    pub fn configure_original_witness(&mut self) -> Result<()> {
        self.inner.configure_original_witness()
    }
    pub fn poll_data_only(&mut self) -> Result<()> {
        self.inner.poll_data_only()
    }
    pub fn poll_exact_redisclosure(
        &mut self,
        request: &DurableConstructionRedisclosureRequestV1,
    ) -> Result<bool> {
        self.inner.poll_exact_redisclosure(request)
    }
    /// True means only an actual Controlled response and local intent are held.
    /// It is deliberately not a complete-history status or financial authority.
    pub fn admission_response_received(&self) -> Result<bool> {
        self.inner.admission_response_received()
    }
    pub fn begin_admission_history_audit(&mut self) -> Result<()> {
        self.inner.begin_admission_history_audit()
    }
    pub fn poll_exact_import(
        &mut self,
        request: &DurableReviewDeliveryRequestV1,
        identity: &wholepact_protocol::durable_proposal_v1::FixedProposalIdentityV1,
    ) -> Result<bool> {
        self.inner.poll_exact_import(request, identity)
    }
    pub fn poll_admission_review(
        &mut self,
        request:&crate::authority_bridge::durable_delivery_admission_ipc_v2::DurableDeliveryAdmissionRequestV2,
    ) -> Result<Option<wholepact_authority::OwnerControlRequest>> {
        self.inner.poll_admission_review(request)
    }
    pub fn approve_admission(&mut self) -> Result<()> {
        self.inner.approve_admission()
    }
    pub fn admission_status(&self)->Result<Option<crate::authority_bridge::durable_delivery_admission_ipc_v2::DurableDeliveryAdmissionStatusV2>>{
        self.inner.admission_status()
    }
    pub fn take_failure(&mut self) -> Option<DurableDeliveryFailureV2> {
        self.inner.take_failure()
    }
    pub fn require_financial_routes_denied(&mut self) -> Result<()> {
        self.inner.require_financial_routes_denied()
    }
    pub fn close_original_entry(self) -> Result<EphemeralAcknowledgedBornV1> {
        Ok(EphemeralAcknowledgedBornV1 {
            original: self.inner.close()?,
        })
    }
    pub fn close_existing_entry(self) -> Result<()> {
        self.inner.close_existing()
    }
}
pub use crate::native_ui::runtime::durable_proposal_qualification_v1::DurableDeliveryReopenSelectorV2;
impl EphemeralDurableDeliveryNativeV2 {
    pub fn close_preserving_originals(self) -> Result<DurableDeliveryReopenSelectorV2> {
        self.inner.close_preserving_originals()
    }
    pub fn reopen_original_selector(
        selector: DurableDeliveryReopenSelectorV2,
    ) -> std::result::Result<Self, DurableNativeEntryFailureV1> {
        let expected_account = selector.account_id;
        let version = selector.version;
        let reopened = Self::open_existing_durable_delivery_v2(
            selector.root,
            selector.proposal,
            selector.aggregate_budget_zatoshis,
            selector.owner_setup_json,
        )?;
        if version != 2 || reopened.scope().account_id != expected_account {
            return Err(DurableNativeEntryFailureV1::for_delivery_selector_mismatch());
        }
        Ok(reopened)
    }
}

/// Qualification custody of an actual production V3 controller. No public
/// constructor, synthetic native decision or source-authority conversion.
pub struct EphemeralClosedDeliveryNativeV3 {
    inner: crate::native_ui::runtime::durable_proposal_qualification_v1::ClosedDeliveryNativeFixtureV3,
}
impl EphemeralDurableDeliveryNativeV2 {
    pub fn poll_closed_receive_review_v3(
        &mut self,
        request: &DurableReviewDeliveryRequestV1,
        fixed: &wholepact_protocol::durable_proposal_v1::FixedProposalIdentityV1,
        payload_digest: &str,
        payload_bytes: u64,
        delivery: &wholepact_authority::durable_delivery_scope_v2::DurableDeliveryPlanV2,
        materials: &[wholepact_authority::durable_delivery_scope_v2::DurableDeliveryMaterialScopeRefV2],
    ) -> Result<bool> {
        self.inner.poll_closed_receive_review_v3(request, fixed, payload_digest, payload_bytes, delivery, materials)
    }
    pub fn into_closed_delivery_v3(self) -> Result<EphemeralClosedDeliveryNativeV3> {
        Ok(EphemeralClosedDeliveryNativeV3 { inner: self.inner.into_closed_delivery_v3()? })
    }
}
impl EphemeralClosedDeliveryNativeV3 {
    pub fn open_history_existing(selector: DurableDeliveryReopenSelectorV2, prior: crate::authority_bridge::durable_review_ipc_v3::RecipientIntentV3) -> Result<Self> {
        Ok(Self { inner: crate::native_ui::runtime::durable_proposal_qualification_v1::ClosedDeliveryNativeFixtureV3::open_history_existing(selector, prior)? })
    }
    pub fn provider(&self) -> Result<wholepact_signer_origin::InstalledSignerProvider> { self.inner.provider() }
    pub fn endpoint(&self) -> Result<std::path::PathBuf> { self.inner.endpoint() }
    pub fn deadline(&self) -> Result<Instant> { self.inner.deadline() }
    pub fn poll_data_only(&mut self) -> Result<()> { self.inner.poll() }
    pub fn poll_verified_import(&mut self, fixed: &wholepact_protocol::durable_proposal_v1::FixedProposalIdentityV1) -> Result<bool> {
        self.inner.poll_verified_import(fixed)
    }
    pub fn poll_admission_review(&mut self) -> Result<Option<wholepact_authority::OwnerControlRequest>> {
        self.inner.poll_admission_review()
    }
    pub fn approve_conditional_admission(&mut self) -> Result<()> { self.inner.approve_conditional_admission() }
    pub fn admission_pending(&mut self) -> Result<bool> { self.inner.admission_pending() }
    pub fn begin_history_audit(&mut self) -> Result<()> { self.inner.begin_history_audit() }
    pub fn poll_history_audit(&mut self) -> Result<bool> { self.inner.poll_history_audit() }
    pub fn status(&self) -> Result<crate::authority_bridge::durable_delivery_admission_ipc_v3::DurableDeliveryAdmissionStatusV3> { self.inner.status() }
    pub fn require_financial_routes_denied(&mut self) -> Result<()> { self.inner.require_financial_routes_denied() }
    pub fn close_existing_entry(self) -> Result<()> { self.inner.close_existing() }
    pub fn close_preserving_originals(self) -> Result<DurableDeliveryReopenSelectorV2> { self.inner.close_preserving_originals() }
}

pub use crate::native_ui::runtime::durable_proposal_qualification_v1::FinancialQualificationPhaseV1;
pub use crate::native_ui::runtime::financial_v1::diagnostics::{FinancialNativeDiagnosticV1,FinancialNativeStageV1,FinancialNativeComponentV1,FinancialNativeErrorClassV1};
/// Classifies an actual qualification failure without retaining data or granting authority.
pub fn classify_financial_native_failure_v1(stage:FinancialNativeStageV1,error:&crate::Error)->Option<FinancialNativeDiagnosticV1>{
    use crate::native_ui::runtime::financial_v1::diagnostics;
    let scope=diagnostics::Scope::begin(stage);
    diagnostics::signer(error);
    scope.failure()
}

/// Actual synthetic native controller only. Every approval drives the existing
/// reviewed exact native click path; no permission DTO or replacement source.
pub struct EphemeralFinancialContinuationNativeV1 {
    inner:crate::native_ui::runtime::durable_proposal_qualification_v1::FinancialNativeFixtureV1,
}
impl EphemeralClosedDeliveryNativeV3 {
    pub fn into_financial_continuation_v1(self,wallet_setup_json:String)->Result<EphemeralFinancialContinuationNativeV1>{Ok(EphemeralFinancialContinuationNativeV1{inner:self.inner.into_financial_continuation_v1(wallet_setup_json)?})}
}
impl EphemeralFinancialContinuationNativeV1 {
    pub fn progress_observer_v1(&self)->Option<FinancialNativeProgressObserverV1>{self.inner.progress_observer_v1()}
    pub fn last_failure_v1(&self)->Option<FinancialNativeDiagnosticV1>{self.inner.last_failure_v1()}
    /// Moves the already established fixture's installed-process trust owner
    /// once, instead of constructing trust from a source receipt or DTO.
    pub fn provider(&self)->Result<wholepact_signer_origin::InstalledSignerProvider>{self.inner.provider()}
    pub fn endpoint(&self)->Result<std::path::PathBuf>{self.inner.endpoint()}
    pub fn deadline(&self)->Result<Instant>{self.inner.deadline()}
    pub fn poll(&mut self)->Result<FinancialQualificationPhaseV1>{self.inner.poll()}
    pub fn approve_current_review(&mut self)->Result<()>{self.inner.approve_current_review()}
    pub fn send_pending_continuation(&mut self)->Result<()>{self.inner.send_pending_continuation()}
    pub fn pending_continuation_request(&self)->Result<Option<wholepact_authority::OwnerControlRequest>>{self.inner.pending_continuation_request()}
    pub fn pending_activation_request(&self)->Result<Option<wholepact_authority::OwnerControlRequest>>{self.inner.pending_activation_request()}
    pub fn result_request(&self)->Result<crate::authority_bridge::financial_continuation_v1::FinancialResultRequestV1>{self.inner.result_request()}
    pub fn close_preserving_originals(self)->Result<DurableDeliveryReopenSelectorV2>{self.inner.close_preserving_originals()}
}

pub use crate::native_ui::runtime::financial_v1::diagnostics::{FinancialAuthorityCallV1, FinancialAuthorityCostV1, FinancialAuthorityStageV1, FinancialAuthorityCheckSiteV1, FinancialAuthorityCheckpointV1, FinancialAuthoritySelectedLimitV1};

pub use crate::native_ui::runtime::financial_v1::diagnostics::{FinancialNativeProgressObserverV1,FinancialNativeProgressV1};

pub use crate::native_ui::runtime::durable_proposal_qualification_v1::DurableResultQualificationPhaseV2;
/// Existing synthetic worker entry, with genuine result-only production UI.
/// This is not by itself an OS-process-restart or complete two-owner proof.
pub struct EphemeralDurableResultNativeV2 {
    inner: crate::native_ui::runtime::durable_proposal_qualification_v1::DurableResultNativeFixtureV2,
}
impl EphemeralDurableResultNativeV2 {
    pub fn open_existing(selector: DurableDeliveryReopenSelectorV2) -> Result<Self> {
        Ok(Self { inner: crate::native_ui::runtime::durable_proposal_qualification_v1::DurableResultNativeFixtureV2::open_existing(selector)? })
    }
    pub fn provider(&self) -> Result<wholepact_signer_origin::InstalledSignerProvider> { self.inner.provider() }
    pub fn endpoint(&self) -> Result<std::path::PathBuf> { self.inner.endpoint() }
    pub fn deadline(&self) -> Result<Instant> { self.inner.deadline() }
    pub fn result_request(&self) -> Result<crate::authority_bridge::financial_continuation_v1::DurableFinancialResultRequestV2> { self.inner.result_request() }
    pub fn poll(&mut self) -> Result<DurableResultQualificationPhaseV2> { self.inner.poll() }
    pub fn approve_current_review(&mut self) -> Result<()> { self.inner.approve_current_review() }
    pub fn close_preserving_originals(self) -> Result<DurableDeliveryReopenSelectorV2> { self.inner.close_preserving_originals() }
}

pub use crate::native_ui::runtime::durable_proposal_qualification_v1::PreservedDurablePairV2;
impl EphemeralClosedDeliveryNativeV3 {
    pub fn into_financial_continuation_reopened_v2(
        self, wallet_setup_json: String,
        origin: wholepact_authority::native_witness_owner::EphemeralWitnessOriginV1,
        pair: std::sync::Arc<PreservedDurablePairV2>,
    ) -> Result<EphemeralFinancialContinuationNativeV1> {
        Ok(EphemeralFinancialContinuationNativeV1 { inner: self.inner.into_financial_continuation_reopened_v2(wallet_setup_json, origin, pair)? })
    }
}
impl EphemeralFinancialContinuationNativeV1 {
    pub fn close_preserving_reopened_v2(self) -> Result<DurableDeliveryReopenSelectorV2> {
        self.inner.close_preserving_reopened_v2()
    }
}
impl EphemeralDurableResultNativeV2 {
    pub fn open_existing_in_pair(selector: DurableDeliveryReopenSelectorV2, pair: std::sync::Arc<PreservedDurablePairV2>) -> Result<Self> {
        Ok(Self { inner: crate::native_ui::runtime::durable_proposal_qualification_v1::DurableResultNativeFixtureV2::open_existing_in_pair(selector, pair)? })
    }
}

pub use crate::native_ui::runtime::durable_proposal_qualification_v1::{DurableResultGrantProbeV2, DurableResultGrantProbeOutcomeV2};
impl EphemeralDurableResultNativeV2 {
    pub fn probe_grant(&mut self, probe: DurableResultGrantProbeV2, other_stream: Option<std::os::unix::net::UnixStream>, stop: &std::sync::atomic::AtomicBool) -> Result<DurableResultGrantProbeOutcomeV2> {
        self.inner.probe_grant(probe, other_stream, stop)
    }
}

pub use crate::native_ui::runtime::durable_proposal_qualification_v1::{StartedFinancialCustodyV2, StartedAuditStageV2, audit_started_after_restart_v2, audit_started_after_restart_observed_v2};
impl EphemeralFinancialContinuationNativeV1 {
    pub fn capture_and_arm_started_v2(&mut self, outer_deadline: std::time::Instant) -> Result<StartedFinancialCustodyV2> {
        self.inner.capture_and_arm_started_v2(outer_deadline)
    }
}
