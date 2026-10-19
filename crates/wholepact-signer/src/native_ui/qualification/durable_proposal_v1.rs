//! Finite synthetic delivery through the genuine NEW durable native entry.
//!
//! This is a runtime child, not an authority factory. It owns a genuinely born,
//! never-funded temporary account, drives the maintained native review machine,
//! and drains every real owner before returning the historical fixture. No FVK,
//! decision, writer credential, wallet ticket or signing capability is exposed.
//! A host leaf must independently own encrypted intake, proof and exact union.

#[path = "durable_proposal_v1/witness_wait_v1.rs"]
mod witness_wait_v1;

pub use super::durable_witness_v1::{
    DurableAdmissionCallFailureV1, DurableAdmissionCallbackStageV1, DurableAdmissionCompletionV1,
    DurableAdmissionDispatchFailureV1, DurableAdmissionDispatchMeasurementV1,
    DurableAdmissionDispatchStageV1, DurableAdmissionHistoryFailureV1,
    DurableAdmissionPreparationFailureV1, DurableAdmissionPreparationStageV1,
    DurableAdmissionRetentionV1,
};
use super::durable_witness_v1::{DurableWitnessPreparedV1, QualificationDurableWitnessCompletionV1};
use super::*;
use crate::authority_bridge::durable_flow_diagnostics_v1::{
    self as flow_diag_v1, DurableFlowDiagnosticV1, DurableFlowFailureV1,
    DurableFlowObservationTokenV1, DurableFlowOperationV1, DurableFlowResultV1, DurableFlowStageV1,
};
use crate::authority_bridge::{
    durable_construction_v1::{
        DurableConstructionCaptureRequestV1, DurableConstructionHistoryRequestV1,
        DurableConstructionRedisclosureRequestV1, DurableConstructionRequestV1,
    },
    durable_review_ipc_v1::DurableReviewDeliveryRequestV1,
    ipc::HistoryRequest,
    preconstruction_ipc::PreconstructionRequest,
    AuthorizationCommit,
};
use crate::native_ui::pending_enrollment::born_pending_continuation::AcknowledgedBornFixture;
use std::{collections::BTreeSet, ffi::OsString, path::PathBuf, time::Instant};
use wholepact_protocol::durable_proposal_v1::FixedProposalIdentityV1;
use wholepact_signer_origin::{InstalledSignerProvider, PairScope};

const EPOCH: u64 = 1;

/// Public correlation only. These exact references never restore a session.
#[derive(Clone, PartialEq, Eq)]
pub struct DurableNativeRecordsV1 {
    pub enrollment_ref: String,
    pub accepted_manifest_ref: String,
}

/// Closed synthetic diagnostics only. No source path, account, request or
/// underlying error text is exposed by this finite phase classification.
#[derive(Clone, Copy)]
pub enum DurableNativeEntryStageV1 {
    NativeOwnerCheck,
    VaultOpen,
    RetainedEnrollment,
    OriginalCommit,
    JournalOpen,
    SourceCheck,
    RuntimeActivation,
    WorkerResult,
    EndpointCreate,
    EndpointBind,
    EndpointPublish,
    PostEndpointSourceCheck,
    FixturePreflight,
    FixturePostActivation,
}

pub struct DurableNativeEntryFailureV1 {
    stage: DurableNativeEntryStageV1,
    error: Error,
}
impl DurableNativeEntryFailureV1 {
    pub fn stage(&self) -> DurableNativeEntryStageV1 {
        self.stage
    }
    pub fn into_error(self) -> Error {
        self.error
    }
}

impl From<super::durable_entry_v1::DurableEntryFailureStageV1> for DurableNativeEntryStageV1 {
    fn from(stage: super::durable_entry_v1::DurableEntryFailureStageV1) -> Self {
        use super::durable_entry_v1::DurableEntryFailureStageV1 as S;
        match stage {
            S::NativeOwnerCheck => Self::NativeOwnerCheck,
            S::VaultOpen => Self::VaultOpen,
            S::RetainedEnrollment => Self::RetainedEnrollment,
            S::OriginalCommit => Self::OriginalCommit,
            S::JournalOpen => Self::JournalOpen,
            S::SourceCheck => Self::SourceCheck,
            S::RuntimeActivation => Self::RuntimeActivation,
            S::WorkerResult => Self::WorkerResult,
            S::EndpointCreate => Self::EndpointCreate,
            S::EndpointBind => Self::EndpointBind,
            S::EndpointPublish => Self::EndpointPublish,
            S::PostEndpointSourceCheck => Self::PostEndpointSourceCheck,
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Phase {
    Pair,
    Paired,
    Accepted,
    Disclosure,
    Disclosed,
    Imported,
    AdmissionPrepared,
    Admitted,
    AcquireReplyLost,
    AcquireRetriedPending,
    FinancialImported,
    Signed,
}

enum ExpectedDisclosure {
    Initial(PreconstructionRequest),
    Durable(DurableConstructionRequestV1),
    Capture(DurableConstructionCaptureRequestV1, PreconstructionRequest),
}

pub(in crate::native_ui) struct DurableNativeFixtureV1 {
    // Drop drains this runtime before releasing the temporary source lifetime.
    runtime: NativeRuntime,
    original: Option<AcknowledgedBornFixture>,
    proposal: Proposal,
    scope: PairScope,
    budget: u64,
    phase: Phase,
    expected: Option<ExpectedDisclosure>,
    entry: String,
    original_inventory: BTreeSet<OsString>,
    // Data-only assertions for this fixture's completed original. Neither the
    // tuple nor these fingerprints can restore a production continuation.
    signed: Option<(HistoryRequest, AuthorizationCommit, Vec<(u64, [u8; 32])>)>,
    // Inert correlations only. These never reconstruct a review or permission.
    admission: Option<wholepact_authority::OwnerControlRequest>,
    acquire_reply_loss: Option<AcquireReplyLossCorrelationV1>,
    reconciled_records: Option<DurableNativeRecordsV1>,
    reconciled_writer: Option<(Arc<()>, wholepact_authority::WriterSessionReceipt)>,
    // This owner is inert data only and survives the real OpenAccount close.
    flow_collector: flow_diag_v1::DurableFlowCollectorV1,
    // Present only for an explicitly observed fresh fixture. The captured
    // deadline is data and never substitutes for an operational owner check.
    lifecycle: Option<flow_diag_v1::DurableLifecycleObserverV1>,
    lifecycle_redisclosure_pending: bool,
    flow_observation: Option<flow_diag_v1::DurableFlowObserverV1>,
    // Inert exact-attempt observation only. A failed caller still owns the
    // original Error; this survives solely until the existing Drop drain.
    flow_pending_drain: Option<flow_diag_v1::DurableFlowObserverV1>,
    flow_service: Option<flow_diag_v1::DurableFlowJobObservationV1>,
    flow_import_expected: Option<super::durable_review_v1::DurableFlowImportExpectationV1>,
}

/// Expected synthetic loss, not retry authority. The original operational Error
/// and its actual finite diagnostic remain owned, unformatted and unserialized.
pub struct DurableAcquireReplyLossV1 {
    error: Error,
    diagnostic: DurableFlowDiagnosticV1,
}
impl DurableAcquireReplyLossV1 {
    pub fn error(&self) -> &Error {
        &self.error
    }
    pub fn diagnostic(&self) -> &DurableFlowDiagnosticV1 {
        &self.diagnostic
    }
    pub fn into_error(self) -> Error {
        self.error
    }
    pub fn is_expected_loss(&self) -> bool {
        acquire_loss_diagnostic_v1(&self.error, &self.diagnostic)
    }
}

// Only inert identity/equality data. No retained source, workspace, approved
// object, client, session key or authority-producing constructor is exposed.
struct AcquireReplyLossCorrelationV1 {
    entry: String,
    records: DurableNativeRecordsV1,
    source_markers: [usize; 3],
    writer: Arc<()>,
    owner: Arc<()>,
    deadline: Instant,
    ledger: Vec<(u64, [u8; 32])>,
    digest: String,
    review_deadline: Instant,
    history_digest: String,
    first_attempt: u64,
    retry_started: bool,
}
fn acquire_immutable_equal_v1(
    before: &AcquireReplyLossCorrelationV1,
    entry: &str,
    records: &DurableNativeRecordsV1,
    source_markers: [usize; 3],
    writer: &Arc<()>,
    owner: &Arc<()>,
    deadline: Instant,
    ledger: &[(u64, [u8; 32])],
) -> bool {
    before.entry == entry
        && &before.records == records
        && before.source_markers == source_markers
        && Arc::ptr_eq(&before.writer, writer)
        && Arc::ptr_eq(&before.owner, owner)
        && before.deadline == deadline
        && before.ledger == ledger
        && ledger.len() == 14
}
fn acquire_retry_phase_v1(phase: Phase, retry_started: bool) -> bool {
    phase == Phase::AcquireReplyLost && !retry_started
}
fn acquire_idle_v1(flags: [bool; 12]) -> bool {
    !flags.into_iter().any(|value| value)
}
#[derive(Clone, Copy)]
struct AcquireLossFactsV1 {
    uncertain: bool,
    complete: bool,
    purpose: Option<flow_diag_v1::DurableFlowJobPurposeV1>,
    result: DurableFlowResultV1,
    receive: flow_diag_v1::DurableFlowReceiveV1,
    suppressed: bool,
    acquire_failed: bool,
    other_calls: bool,
    lower: Option<(
        flow_diag_v1::DurableFlowTransportPurposeV1,
        flow_diag_v1::DurableFlowTransportStageV1,
        Option<wholepact_authority::transport::history_diagnostics_v1::CheckedHistoryIoKindV1>,
    )>,
    callback_failed: bool,
    lower_authority_uncertain: bool,
}
fn acquire_loss_facts_v1(facts: AcquireLossFactsV1) -> bool {
    use flow_diag_v1::{
        DurableFlowJobPurposeV1 as J, DurableFlowReceiveV1 as R,
        DurableFlowTransportPurposeV1 as P, DurableFlowTransportStageV1 as S,
    };
    use wholepact_authority::transport::history_diagnostics_v1::CheckedHistoryIoKindV1 as I;
    facts.uncertain
        && facts.complete
        && facts.purpose == Some(J::Acquire)
        && facts.result == DurableFlowResultV1::ReturnedErr
        && facts.receive == R::Received
        && !facts.suppressed
        && facts.acquire_failed
        && !facts.other_calls
        && facts.lower == Some((P::Acquire, S::ResponseRead, Some(I::Closed)))
        && !facts.callback_failed
        && facts.lower_authority_uncertain
}
fn acquire_loss_diagnostic_v1(error: &Error, diagnostic: &DurableFlowDiagnosticV1) -> bool {
    use flow_diag_v1::DurableFlowCallOutcomeV1 as C;
    let calls = diagnostic.call_outcomes();
    let lower = diagnostic.lower_call_measurement();
    acquire_loss_facts_v1(AcquireLossFactsV1 {
        uncertain: matches!(error, Error::Uncertain),
        complete: diagnostic.operation() == DurableFlowOperationV1::WriterReconcile
            && diagnostic.fixture_result() == DurableFlowResultV1::ReturnedErr
            && !diagnostic.incomplete()
            && !diagnostic.clamped()
            && diagnostic.terminal_error().is_none(),
        purpose: diagnostic.completion().purpose(),
        result: diagnostic.completion().result(),
        receive: diagnostic.completion().receive(),
        suppressed: diagnostic.completion().presentation()
            == flow_diag_v1::DurableFlowPresentationV1::Suppressed,
        acquire_failed: calls.writer_acquire() == C::ReturnedErr,
        other_calls: [
            calls.writer_activate(),
            calls.active_verify(),
            calls.reconciliation(),
            calls.session_invalidation(),
            calls.release(),
            calls.request_retention(),
            calls.reservation(),
            calls.permit_retention(),
            calls.key_use(),
            calls.result_retention(),
        ]
        .into_iter()
        .any(|call| call != C::NotObserved),
        lower: lower.map(|lower| (lower.purpose(), lower.stage(), lower.io_kind())),
        callback_failed: lower.is_some_and(|lower| lower.callback_stage().is_some()),
        lower_authority_uncertain: lower.is_some_and(|lower| {
            lower.authority_code() == flow_diag_v1::DurableFlowAuthorityCodeV1::Uncertain
        }),
    })
}

struct DurableFixtureAdmissionObservationV1 {
    attempt: Option<u64>,
    digest: Option<String>,
    stage: DurableAdmissionDispatchStageV1,
    original_is_operational: bool,
}

pub(in crate::native_ui) struct DurableFinancialImportWaitV1<'a> {
    fixture: &'a mut DurableNativeFixtureV1,
    token: &'a DurableFlowObservationTokenV1,
    request: &'a DurableReviewDeliveryRequestV1,
    identity: &'a FixedProposalIdentityV1,
    deadline: Instant,
    state: witness_wait_v1::PollState,
}
impl DurableFinancialImportWaitV1<'_> {
    pub(in crate::native_ui) fn deadline(&self) -> Instant {
        self.deadline
    }
    pub(in crate::native_ui) fn poll(&mut self) -> Result<bool> {
        let token = self.token;
        let request = self.request;
        let identity = self.identity;
        self.fixture.observe_lifecycle_once_v1(
            flow_diag_v1::DurableLifecyclePointV1::FinancialImportPollStart,
        );
        if self.fixture.matching_flow_v1(token).is_some()
            && self
                .fixture
                .flow_import_expected
                .as_ref()
                .is_none_or(|expected| !expected.matches_poll(request, identity, EPOCH))
        {
            token.observer().mark_incomplete();
        }
        let original = self.state.poll(
            self.fixture,
            || Error::ReviewMismatch,
            |fixture| fixture.pending_wait_live_v1(),
            |fixture| {
                fixture.measure_pending_wait_v1(
                    flow_diag_v1::DurablePendingWaitKindV1::Poll,
                    |fixture| fixture.poll_financial_import_pending_v1(request, identity),
                )
            },
            |fixture| {
                fixture.pending_wait_full_exit_v1()?;
                let records = fixture.records_data_v1()?;
                if request.enrollment_ref != records.enrollment_ref
                    || request.accepted_manifest_ref != records.accepted_manifest_ref
                {
                    return Err(Error::ReviewMismatch);
                }
                fixture.phase = Phase::FinancialImported;
                fixture.observe_lifecycle_once_v1(
                    flow_diag_v1::DurableLifecyclePointV1::FinancialImportComplete,
                );
                Ok(())
            },
        );
        DurableNativeFixtureV1::observe_fixture_result_v1(
            self.fixture.matching_flow_v1(token),
            DurableFlowStageV1::FixtureState,
            &original,
        );
        original
    }
}

pub(in crate::native_ui) struct DurableDisclosureWaitV1<'a> {
    fixture: &'a mut DurableNativeFixtureV1,
    deadline: Instant,
    state: witness_wait_v1::PollState,
}
impl DurableDisclosureWaitV1<'_> {
    pub(in crate::native_ui) fn deadline(&self) -> Instant {
        self.deadline
    }
    pub(in crate::native_ui) fn poll(&mut self) -> Result<bool> {
        self.state.poll(
            self.fixture,
            || Error::ReviewMismatch,
            |fixture| fixture.pending_wait_live_v1(),
            |fixture| {
                fixture.measure_pending_wait_v1(
                    flow_diag_v1::DurablePendingWaitKindV1::Poll,
                    |fixture| fixture.poll_disclosure_pending_v1(),
                )
            },
            |fixture| fixture.pending_wait_full_exit_v1(),
        )
    }
}

// Inert correlation at the historical branch's return boundary, not a source,
// native decision or session factory. The caller must first execute and drain
// the real authenticated history operation. A prepared review is not history.
fn require_historical_admission_observation_v1(
    expected: &wholepact_authority::OwnerControlRequest,
    observed: Option<&wholepact_authority::OwnerControlRequest>,
    pending_review: bool,
    witness_job: bool,
    writer_receipt: bool,
    writer_reconciled: bool,
) -> Result<()> {
    if pending_review
        || witness_job
        || writer_receipt
        || writer_reconciled
        || !matches!(
            &expected.control,
            wholepact_authority::OwnerControl::AdmitDurablePaymentV1 { .. }
        )
        || observed != Some(expected)
    {
        return Err(Error::ReviewMismatch);
    }
    Ok(())
}

impl DurableNativeFixtureV1 {
    pub(in crate::native_ui) fn open(
        original: AcknowledgedBornFixture,
        input: ProposalInput,
        budget: u64,
    ) -> std::result::Result<Self, DurableNativeEntryFailureV1> {
        Self::open_with_observation(original, input, budget, false)
    }
    pub(in crate::native_ui) fn open_diagnosed(
        original: AcknowledgedBornFixture,
        input: ProposalInput,
        budget: u64,
    ) -> std::result::Result<Self, DurableNativeEntryFailureV1> {
        Self::open_with_observation(original, input, budget, true)
    }
    fn open_with_observation(
        original: AcknowledgedBornFixture,
        input: ProposalInput,
        budget: u64,
        observe_lifecycle: bool,
    ) -> std::result::Result<Self, DurableNativeEntryFailureV1> {
        let mut stage = DurableNativeEntryStageV1::FixturePreflight;
        Self::open_checked(original, input, budget, &mut stage, observe_lifecycle)
            .map_err(|error| DurableNativeEntryFailureV1 { stage, error })
    }
    fn open_checked(
        original: AcknowledgedBornFixture,
        input: ProposalInput,
        budget: u64,
        stage: &mut DurableNativeEntryStageV1,
        observe_lifecycle: bool,
    ) -> Result<Self> {
        let proposal = Proposal::validate(input).map_err(|_| Error::Verification)?;
        require_plain_two_owner_manifest(&proposal, &original.account_id)?;
        if !original.root.starts_with(original.temporary.path())
            || original.root == original.temporary.path()
            || budget == 0
        {
            return Err(Error::ReviewMismatch);
        }
        let participant = proposal
            .manifest()
            .participants
            .iter()
            .find(|p| p.account_id == original.account_id)
            .ok_or(Error::ReviewMismatch)?;
        let scope = PairScope {
            account_id: original.account_id.clone(),
            agreement_id: proposal.manifest().agreement.agreement_id.clone(),
            participant_id: participant.participant_id.clone(),
            manifest_digest: proposal.manifest_digest().into(),
            history_read: true,
            authorization_export: true,
            preconstruction_export: true,
        };
        // Capture complete quiescent inventory. A live SQLite connection may
        // temporarily create WAL/SHM files; compare again only after full drain.
        // No unknown names, directories or symlinks are filtered from this check.
        let original_inventory = original_inventory(&original.root)?;
        let mut runtime = NativeRuntime::new(None);
        runtime.root = original.root.to_str().ok_or(Error::InvalidData)?.into();
        runtime.password = Zeroizing::new(
            crate::native_ui::birth_workspace::born_roster_v3::SYNTHETIC_PENDING_PASSWORD.into(),
        );
        // The actual focused-click gate must reject before KDF/native creation.
        if runtime.begin_durable_entry_v1(false, EPOCH).is_ok()
            || runtime.begin_durable_entry_v1(true, 0).is_ok()
            || runtime.open.is_some()
            || runtime.durable_entry_job.is_some()
        {
            return Err(Error::ReviewMismatch);
        }
        *stage = DurableNativeEntryStageV1::RuntimeActivation;
        runtime.begin_durable_entry_v1(true, EPOCH)?;
        while runtime.durable_entry_job.is_some() {
            runtime.poll_durable_entry_v1(true, EPOCH);
            std::thread::sleep(Duration::from_millis(2));
        }
        if let Some((failed_stage, error)) = runtime.take_durable_entry_failure_for_qualification()
        {
            *stage = failed_stage.into();
            return Err(error);
        }
        *stage = DurableNativeEntryStageV1::FixturePostActivation;
        let open = runtime.open.as_ref().ok_or(Error::Unavailable)?;
        let source = open
            .durable_born_entry
            .as_ref()
            .ok_or(Error::RecoveryRequired)?;
        source.check_current()?;
        let OpenNativeAuthority::DurableBorn(actual_owner) = &open.authority else {
            return Err(Error::ReviewMismatch);
        };
        if !Arc::ptr_eq(actual_owner, source.native_owner())
            || open.vault.account_id()? != original.account_id
            || source.genesis().identity.account_id != original.account_id
            || open.session.is_some()
            || open.pairing.is_some()
            || open.enrollment.is_some()
            || open.manifest.is_some()
            || open.writer_receipt.is_some()
            || open.writer_reconciled
            || open.ipc.socket_path().starts_with(&original.root)
        {
            return Err(Error::ReviewMismatch);
        }
        let entry = open.authority.binding().entry_digest().to_owned();
        let lifecycle = if observe_lifecycle {
            // Pure projection of the original immutable owner deadline. Do not
            // call the checked deadline getter or add another authority check.
            open.authority
                .binding()
                .deadline()
                .map(flow_diag_v1::DurableLifecycleObserverV1::new)
        } else {
            None
        };
        if let Some(observer) = lifecycle.as_ref() {
            observer.point(flow_diag_v1::DurableLifecyclePointV1::NativeOpenComplete);
        }
        Ok(Self {
            runtime,
            original: Some(original),
            proposal,
            scope,
            budget,
            phase: Phase::Pair,
            expected: None,
            entry,
            original_inventory,
            signed: None,
            admission: None,
            acquire_reply_loss: None,
            reconciled_records: None,
            reconciled_writer: None,
            flow_collector: Default::default(),
            lifecycle,
            lifecycle_redisclosure_pending: false,
            flow_observation: None,
            flow_pending_drain: None,
            flow_service: None,
            flow_import_expected: None,
        })
    }
    fn observe_lifecycle_v1(&self, point: flow_diag_v1::DurableLifecyclePointV1) {
        if let Some(observer) = self.lifecycle.as_ref() {
            observer.point(point);
        }
    }
    fn observe_lifecycle_once_v1(&self, point: flow_diag_v1::DurableLifecyclePointV1) {
        if let Some(observer) = self.lifecycle.as_ref() {
            observer.point_once(point);
        }
    }
    fn measure_pending_wait_v1<T>(
        &mut self,
        kind: flow_diag_v1::DurablePendingWaitKindV1,
        call: impl FnOnce(&mut Self) -> T,
    ) -> T {
        let lifecycle = self.lifecycle.clone();
        flow_diag_v1::observe_pending_wait_v1(lifecycle.as_ref(), kind, || call(self))
    }
    fn pending_wait_full_entry_v1(&mut self) -> Result<()> {
        self.measure_pending_wait_v1(
            flow_diag_v1::DurablePendingWaitKindV1::FullPrecheck,
            |fixture| fixture.check(),
        )
    }
    fn pending_wait_live_v1(&mut self) -> Result<()> {
        self.measure_pending_wait_v1(
            flow_diag_v1::DurablePendingWaitKindV1::Liveness,
            |fixture| fixture.check_pending_witness_v1(),
        )
    }
    fn pending_wait_full_exit_v1(&mut self) -> Result<()> {
        self.measure_pending_wait_v1(
            flow_diag_v1::DurablePendingWaitKindV1::FullPostcheck,
            |fixture| fixture.check(),
        )
    }
    fn check(&self) -> Result<()> {
        let original = self.original.as_ref().ok_or(Error::Locked)?;
        let open = self.runtime.open.as_ref().ok_or(Error::Locked)?;
        let source = open.durable_born_entry.as_ref().ok_or(Error::Locked)?;
        flow_diag_v1::observe_result(
            self.flow_observation.as_ref(),
            DurableFlowStageV1::FixtureState,
            source.check_current(),
        )?;
        if flow_diag_v1::observe_result(
            self.flow_observation.as_ref(),
            DurableFlowStageV1::FixtureState,
            open.vault.account_id(),
        )? != original.account_id
            || open.authority.binding().entry_digest() != self.entry
            || open.authority.binding() != source.native_binding()
        {
            return Err(Error::ReviewMismatch);
        }
        Ok(())
    }
    pub(in crate::native_ui) fn endpoint(&self) -> Result<PathBuf> {
        self.check()?;
        Ok(self
            .runtime
            .open
            .as_ref()
            .ok_or(Error::Locked)?
            .ipc
            .socket_path()
            .to_path_buf())
    }
    pub(in crate::native_ui) fn provider(&self) -> Result<InstalledSignerProvider> {
        self.check()?;
        InstalledSignerProvider::qualification_current_process().map_err(|_| Error::Authentication)
    }
    pub(in crate::native_ui) fn deadline(&self) -> Result<Instant> {
        self.check()?;
        self.runtime
            .open
            .as_ref()
            .ok_or(Error::Locked)?
            .authority
            .binding()
            .bounded_deadline()
    }
    pub(in crate::native_ui) fn scope(&self) -> &PairScope {
        &self.scope
    }
    pub(in crate::native_ui) fn entry_digest(&self) -> &str {
        &self.entry
    }

    /// Only the predetermined exact Pair can be approved. A genuine Status
    /// challenge must subsequently establish possession before enrollment.
    pub(in crate::native_ui) fn poll_pair(&mut self) -> Result<bool> {
        self.check()?;
        if !matches!(self.phase, Phase::Pair | Phase::Paired) {
            return Err(Error::ReviewMismatch);
        }
        self.runtime.poll(EPOCH);
        if let Some(pending) = &self.runtime.pending {
            if self.phase != Phase::Pair
                || !matches!(&pending.operation,
                Operation::Pair(pair) if pair.scope == self.scope)
            {
                return Err(Error::ReviewMismatch);
            }
            approve(&mut self.runtime)?;
            self.phase = Phase::Paired;
        }
        let open = self.runtime.open.as_ref().ok_or(Error::Locked)?;
        if let Some(pairing) = &open.pairing {
            pairing.check_current()?;
            if pairing.peer.scope != self.scope || open.session.is_none() {
                return Err(Error::ReviewMismatch);
            }
            let paired = self.phase == Phase::Paired;
            if paired {
                self.observe_lifecycle_v1(flow_diag_v1::DurableLifecyclePointV1::PairComplete);
            }
            return Ok(paired);
        }
        Ok(false)
    }
    pub(in crate::native_ui) fn accept_exact_manifest(&mut self) -> Result<DurableNativeRecordsV1> {
        self.check()?;
        if self.phase != Phase::Paired {
            return Err(Error::ReviewMismatch);
        }
        self.runtime.proposal = Zeroizing::new(
            serde_json::to_string(self.proposal.input()).map_err(|_| Error::InvalidData)?,
        );
        self.runtime.budget = self.budget.to_string();
        self.runtime.stage_enrollment(EPOCH)?;
        if !matches!(
            self.runtime.pending.as_ref().map(|p| &p.operation),
            Some(Operation::Enroll(_))
        ) {
            return Err(Error::ReviewMismatch);
        }
        approve(&mut self.runtime)?;
        self.runtime.stage_manifest(EPOCH)?;
        if !matches!(
            self.runtime.pending.as_ref().map(|p| &p.operation),
            Some(Operation::Manifest(_))
        ) {
            return Err(Error::ReviewMismatch);
        }
        approve(&mut self.runtime)?;
        let records = self.records()?;
        if self.reconciled_records.as_ref().is_some_and(|old| {
            old.enrollment_ref == records.enrollment_ref
                || old.accepted_manifest_ref == records.accepted_manifest_ref
        }) {
            return Err(Error::ReviewMismatch);
        }
        self.phase = Phase::Accepted;
        self.observe_lifecycle_once_v1(if self.reconciled_writer.is_some() {
            flow_diag_v1::DurableLifecyclePointV1::PostReconcileAcceptComplete
        } else {
            flow_diag_v1::DurableLifecyclePointV1::AcceptComplete
        });
        Ok(records)
    }
    pub(in crate::native_ui) fn records(&self) -> Result<DurableNativeRecordsV1> {
        self.check()?;
        self.records_data_v1()
    }
    // Inert record equality only, called behind the caller's actual full gate.
    fn records_data_v1(&self) -> Result<DurableNativeRecordsV1> {
        let open = self.runtime.open.as_ref().ok_or(Error::Locked)?;
        let enrollment = open.enrollment.as_ref().ok_or(Error::ReviewMismatch)?;
        let manifest = open.manifest.as_ref().ok_or(Error::ReviewMismatch)?;
        if manifest.proposal_input() != self.proposal.input()
            || manifest.enrollment_ref() != enrollment.reference()
        {
            return Err(Error::ReviewMismatch);
        }
        Ok(DurableNativeRecordsV1 {
            enrollment_ref: enrollment.reference().into(),
            accepted_manifest_ref: manifest.reference().into(),
        })
    }
    pub(in crate::native_ui) fn expect_initial_disclosure(
        &mut self,
        request: PreconstructionRequest,
    ) -> Result<()> {
        self.check()?;
        request.validate().map_err(|_| Error::Verification)?;
        let refs = self.records()?;
        if self.phase != Phase::Accepted
            || request.sponsor_policy.is_some()
            || request.scope.proposal != *self.proposal.input()
            || request.scope.account_id != self.scope.account_id
            || request.scope.participant_id != self.scope.participant_id
            || request.enrollment_ref != refs.enrollment_ref
            || request.accepted_manifest_ref != refs.accepted_manifest_ref
        {
            return Err(Error::ReviewMismatch);
        }
        self.expected = Some(ExpectedDisclosure::Initial(request));
        self.lifecycle_redisclosure_pending = false;
        self.phase = Phase::Disclosure;
        Ok(())
    }
    pub(in crate::native_ui) fn expect_durable_disclosure(
        &mut self,
        request: DurableConstructionRequestV1,
    ) -> Result<()> {
        self.check()?;
        request.validate().map_err(|_| Error::Verification)?;
        let refs = self.records()?;
        if self.phase != Phase::Accepted
            || request.scope.version != 2
            || request.scope.proposal != *self.proposal.input()
            || request.scope.account_id != self.scope.account_id
            || request.scope.participant_id != self.scope.participant_id
            || request.enrollment_ref != refs.enrollment_ref
            || request.accepted_manifest_ref != refs.accepted_manifest_ref
        {
            return Err(Error::ReviewMismatch);
        }
        self.expected = Some(ExpectedDisclosure::Durable(request));
        self.lifecycle_redisclosure_pending = false;
        self.phase = Phase::Disclosure;
        Ok(())
    }
    pub(in crate::native_ui) fn expect_durable_capture(
        &mut self,
        request: DurableConstructionCaptureRequestV1,
    ) -> Result<()> {
        self.check()?;
        let Some(ExpectedDisclosure::Initial(initial)) = &self.expected else {
            return Err(Error::ReviewMismatch);
        };
        let refs = self.records()?;
        if self.phase != Phase::Disclosed
            || request.scope.version != 2
            || request.scope.proposal != *self.proposal.input()
            || request.scope.account_id != self.scope.account_id
            || request.scope.participant_id != self.scope.participant_id
            || request.enrollment_ref != refs.enrollment_ref
            || request.accepted_manifest_ref != refs.accepted_manifest_ref
        {
            return Err(Error::ReviewMismatch);
        }
        request.scope.validate().map_err(|_| Error::Verification)?;
        self.expected = Some(ExpectedDisclosure::Capture(request, initial.clone()));
        self.lifecycle_redisclosure_pending = false;
        self.phase = Phase::Disclosure;
        Ok(())
    }
    /// Derive only expected immutable data from the actual original journal.
    /// This does not issue the redisclosure; its separate native decision must
    /// consume the maintained prepared operation from the real IPC request.
    pub(in crate::native_ui) fn expect_redisclosure(
        &mut self,
        request: DurableConstructionRedisclosureRequestV1,
    ) -> Result<()> {
        self.check()?;
        request.validate().map_err(|_| Error::Verification)?;
        let refs = self.records()?;
        if self.phase != Phase::Accepted
            || request.enrollment_ref != refs.enrollment_ref
            || request.accepted_manifest_ref != refs.accepted_manifest_ref
        {
            return Err(Error::ReviewMismatch);
        }
        let open = self.runtime.open.as_ref().ok_or(Error::Locked)?;
        let original = open
            .journal
            .prepare_durable_construction_redisclosure_source_v1(
                &request.original,
                open.session.as_ref().ok_or(Error::Locked)?,
            )
            .map_err(|_| Error::ReviewMismatch)?;
        if original.redisclosure().is_some()
            || original.request().enrollment_ref == refs.enrollment_ref
            || original.request().accepted_manifest_ref == refs.accepted_manifest_ref
        {
            return Err(Error::ReviewMismatch);
        }
        // Attack: the old account is genuine, but its old accepted records are
        // NOT current native authority. Exercise the maintained preparation with
        // the actual current authenticated peer and expect refusal before review.
        // This local negative-only stream never supplies a positive issuer.
        let mut stale = request.clone();
        stale.enrollment_ref = original.request().enrollment_ref.clone();
        stale.accepted_manifest_ref = original.request().accepted_manifest_ref.clone();
        let (rejected_stream, _discarded_peer) =
            std::os::unix::net::UnixStream::pair().map_err(|_| Error::Unavailable)?;
        if crate::native_ui::durable_construction_v1::PreparedDurableConstructionV1::prepare_redisclosure(
            stale, open.pairing.as_ref().ok_or(Error::Locked)?.peer.clone(), rejected_stream,
            &open.journal, open.session.as_ref().ok_or(Error::Locked)?,
            &open.authority.binding(), &open.vault,
        ).is_ok() {
            return Err(Error::ReviewMismatch);
        }
        let grant = &open.pairing.as_ref().ok_or(Error::Locked)?.peer.key_digest;
        let mut expected = original.request().clone();
        expected.operation_id = request.operation_id;
        expected.enrollment_ref = refs.enrollment_ref;
        expected.accepted_manifest_ref = refs.accepted_manifest_ref;
        expected.scope.constructor.authenticated_local_grant_digest = grant.clone();
        expected.scope.prover.authenticated_local_grant_digest = grant.clone();
        self.expected = Some(ExpectedDisclosure::Durable(expected));
        self.lifecycle_redisclosure_pending = self.lifecycle.is_some();
        self.phase = Phase::Disclosure;
        Ok(())
    }
    pub(in crate::native_ui) fn poll_disclosure(&mut self) -> Result<bool> {
        self.check()?;
        if self.phase == Phase::Disclosed {
            return Ok(true);
        }
        if self.phase != Phase::Disclosure {
            return Err(Error::ReviewMismatch);
        }
        self.runtime.poll(EPOCH);
        let Some(pending) = &self.runtime.pending else {
            return Ok(false);
        };
        let captured = self.expected_disclosure_capture_v1(pending)?;
        approve(&mut self.runtime)?;
        if let Some(request) = captured {
            self.expected = Some(ExpectedDisclosure::Durable(request));
        }
        self.phase = Phase::Disclosed;
        self.observe_post_reconcile_disclosure_v1();
        Ok(true)
    }
    pub(in crate::native_ui) fn begin_disclosure_wait(
        &mut self,
    ) -> Result<DurableDisclosureWaitV1<'_>> {
        let (state, deadline) = witness_wait_v1::begin(self, |fixture| {
            fixture.measure_pending_wait_v1(
                flow_diag_v1::DurablePendingWaitKindV1::FullPrecheck,
                |fixture| fixture.deadline(),
            )
        })?;
        Ok(DurableDisclosureWaitV1 {
            fixture: self,
            deadline,
            state,
        })
    }
    fn poll_disclosure_pending_v1(&mut self) -> Result<bool> {
        if self.phase == Phase::Disclosed {
            return Ok(true);
        }
        if self.phase != Phase::Disclosure {
            return Err(Error::ReviewMismatch);
        }
        self.runtime.poll(EPOCH);
        if self.runtime.pending.is_none() {
            return Ok(false);
        }
        // The full original source gate runs only once a real review exists,
        // before its exact request matching and the genuine native approval.
        witness_wait_v1::before_approval(
            self,
            |fixture| fixture.pending_wait_full_entry_v1(),
            |fixture| {
                let pending = fixture
                    .runtime
                    .pending
                    .as_ref()
                    .ok_or(Error::ReviewMismatch)?;
                let captured = fixture.expected_disclosure_capture_v1(pending)?;
                approve(&mut fixture.runtime)?;
                if let Some(request) = captured {
                    fixture.expected = Some(ExpectedDisclosure::Durable(request));
                }
                fixture.phase = Phase::Disclosed;
                fixture.observe_post_reconcile_disclosure_v1();
                Ok(true)
            },
        )
    }
    fn observe_post_reconcile_disclosure_v1(&self) {
        if self.lifecycle_redisclosure_pending && self.reconciled_writer.is_some() {
            self.observe_lifecycle_once_v1(
                flow_diag_v1::DurableLifecyclePointV1::PostReconcileRedisclosureNativeComplete,
            );
        }
    }
    // Request matching and inert capture only; no source or authority check.
    fn expected_disclosure_capture_v1(
        &self,
        pending: &PendingDecision,
    ) -> Result<Option<DurableConstructionRequestV1>> {
        let same = match (&self.expected, &pending.operation) {
            (Some(ExpectedDisclosure::Initial(request)), Operation::Preconstruction(prepared)) => {
                prepared
                    .qualification_request_digest()
                    .map_err(|_| Error::Verification)?
                    == request.digest().map_err(|_| Error::Verification)?
            }
            (
                Some(ExpectedDisclosure::Durable(request)),
                Operation::DurableConstructionV1(prepared),
            ) => {
                prepared
                    .qualification_request_digest()
                    .map_err(|_| Error::Verification)?
                    == request.digest().map_err(|_| Error::Verification)?
            }
            (
                Some(ExpectedDisclosure::Capture(expected, initial)),
                Operation::DurableConstructionV1(prepared),
            ) => {
                let actual = prepared.qualification_request();
                let evidence = actual
                    .material
                    .historical_review_evidence()
                    .map_err(|_| Error::Verification)?;
                let summary = actual.material.review_summary();
                actual.operation_id == expected.operation_id
                    && actual.enrollment_ref == expected.enrollment_ref
                    && actual.accepted_manifest_ref == expected.accepted_manifest_ref
                    && actual.scope == expected.scope
                    && evidence.account_id == self.scope.account_id
                    && evidence.context.anchor_height == initial.scope.anchor_height
                    && summary["historical_source"]["source_id"].as_str()
                        == Some(initial.scope.provider.source_id.as_str())
                    && summary["historical_source"]["endpoint"].as_str()
                        == Some(initial.scope.provider.endpoint.as_str())
                    && summary["historical_source"]["trust_profile"].as_str()
                        == Some(initial.scope.provider.trust_profile.as_str())
                    && evidence.inputs.len()
                        == self
                            .proposal
                            .manifest()
                            .inputs
                            .iter()
                            .filter(|input| input.account_id == self.scope.account_id)
                            .count()
                    && evidence.inputs.iter().all(|note| {
                        self.proposal.manifest().inputs.iter().any(|input| {
                            input.account_id == self.scope.account_id
                                && input.input_id == note.input_id
                                && input.amount.as_zatoshis() == note.value_zatoshis
                        })
                    })
            }
            _ => false,
        };
        if !same {
            return Err(Error::ReviewMismatch);
        }
        let captured = match &pending.operation {
            Operation::DurableConstructionV1(prepared) => {
                Some(prepared.qualification_request().clone())
            }
            _ => None,
        };
        Ok(captured)
    }
    /// Assert the maintained native append committed its exact immutable request,
    /// not just that a review click returned. No outbox bytes leave via this API.
    pub(in crate::native_ui) fn durable_disclosure_committed(&self) -> Result<String> {
        self.check()?;
        let Some(ExpectedDisclosure::Durable(request)) = &self.expected else {
            return Err(Error::ReviewMismatch);
        };
        if self.phase != Phase::Disclosed {
            return Err(Error::ReviewMismatch);
        }
        let open = self.runtime.open.as_ref().ok_or(Error::Locked)?;
        let outbox = open
            .journal
            .durable_construction_history_v1(
                &DurableConstructionHistoryRequestV1 {
                    operation_id: request.operation_id.clone(),
                    expected_request_digest: request.digest().map_err(|_| Error::Verification)?,
                },
                open.session.as_ref().ok_or(Error::Locked)?,
            )
            .map_err(|_| Error::ReviewMismatch)?;
        if outbox.request() != request {
            return Err(Error::ReviewMismatch);
        }
        if self.lifecycle_redisclosure_pending {
            self.observe_lifecycle_v1(flow_diag_v1::DurableLifecyclePointV1::RedisclosureComplete);
        }
        Ok(outbox.reference().into())
    }
    pub(in crate::native_ui) fn configure_wallet(&mut self, setup_json: &str) -> Result<()> {
        self.check()?;
        if !matches!(self.phase, Phase::Accepted | Phase::Disclosed)
            || self.runtime.pending.is_some()
        {
            return Err(Error::ReviewMismatch);
        }
        self.runtime.wallet_setup = Zeroizing::new(setup_json.into());
        self.runtime.stage_wallet_setup(EPOCH)?;
        if !matches!(
            self.runtime.pending.as_ref().map(|p| &p.operation),
            Some(Operation::Wallet(_))
        ) {
            return Err(Error::ReviewMismatch);
        }
        approve(&mut self.runtime)
    }
    /// Separate exact new-profile helper. The old generic helper and the
    /// import-only baseline do not gain a permissive operation fallback.
    pub(in crate::native_ui) fn configure_durable_wallet(
        &mut self,
        setup_json: &str,
    ) -> Result<()> {
        self.check()?;
        let open = self.runtime.open.as_ref().ok_or(Error::Locked)?;
        if !matches!(self.phase, Phase::Accepted | Phase::Disclosed)
            || self.runtime.pending.is_some()
            || !open.writer_reconciled
            || open.writer_receipt.is_none()
            || open.wallet.is_some()
            || open.wallet_job.is_some()
            || open.durable_wallet_job.is_some()
        {
            return Err(Error::ReviewMismatch);
        }
        self.runtime.wallet_setup = Zeroizing::new(setup_json.into());
        self.runtime.stage_wallet_setup(EPOCH)?;
        if !matches!(
            self.runtime.pending.as_ref().map(|p| &p.operation),
            Some(Operation::DurableBornWalletV1(_))
        ) {
            return Err(Error::ReviewMismatch);
        }
        approve(&mut self.runtime)?;
        self.runtime
            .open
            .as_ref()
            .ok_or(Error::Locked)?
            .wallet
            .as_ref()
            .ok_or(Error::ReviewMismatch)?
            .check_current()?;
        let original = self.check();
        if original.is_ok() {
            self.observe_lifecycle_once_v1(
                flow_diag_v1::DurableLifecyclePointV1::ViewingSetupComplete,
            );
        }
        original
    }
    /// Uses only the credential lifetime retained by this original nominal
    /// witness fixture; neither arbitrary paths nor caller witness pins enter.
    pub(in crate::native_ui) fn configure_original_witness(&mut self) -> Result<()> {
        self.check()?;
        let original = self.original.as_ref().ok_or(Error::Locked)?;
        let open = self.runtime.open.as_ref().ok_or(Error::Locked)?;
        let source = open.durable_born_entry.as_ref().ok_or(Error::Locked)?;
        let descriptor = source.original_witness_disclosure()?;
        let origin = original.credentials.origin();
        if descriptor.endpoint != origin.endpoint
            || descriptor.witness_id != origin.witness_id
            || descriptor.pinned_server_certificate_digest != origin.server_certificate_digest
        {
            return Err(Error::ReviewMismatch);
        }
        let setup = |owner: bool| -> Result<Zeroizing<String>> {
            Ok(Zeroizing::new(serde_json::to_string(&serde_json::json!({
                "schema_version": 1, "endpoint": descriptor.endpoint,
                "server_name": descriptor.server_name, "witness_id": descriptor.witness_id,
                "account_id": descriptor.account_id, "network_profile_id": descriptor.network_profile_id,
                "policy_digest": descriptor.policy_digest,
                "pinned_server_certificate_digest": descriptor.pinned_server_certificate_digest,
                "trusted_server_root_der": origin.trusted_server_root_file,
                "client_certificate_der": if owner { &origin.owner_certificate_file } else { &origin.writer_certificate_file },
                "client_private_key_pkcs8_der": if owner { &origin.owner_key_file } else { &origin.writer_key_file },
                "operator_name": "Synthetic original never-funded witness",
                "retention_statement": "Exact temporary qualification original only"
            })).map_err(|_| Error::InvalidData)?))
        };
        let writer = setup(false)?;
        let owner = setup(true)?;
        self.runtime.witness_setup = writer;
        self.runtime.stage_witness_setup(EPOCH)?;
        approve(&mut self.runtime)?;
        self.runtime.owner_witness_setup = owner;
        self.runtime.stage_owner_witness_setup(EPOCH)?;
        let result = approve(&mut self.runtime);
        if result.is_ok() {
            self.observe_lifecycle_v1(flow_diag_v1::DurableLifecyclePointV1::WitnessSetupComplete);
        }
        result
    }
    pub(in crate::native_ui) fn prepare_durable_admission(
        &mut self,
    ) -> std::result::Result<
        wholepact_authority::OwnerControlRequest,
        DurableAdmissionPreparationFailureV1,
    > {
        use DurableAdmissionPreparationStageV1 as S;
        let mut stage = S::FixtureState;
        let mut attempt = None;
        let result = (|| -> Result<wholepact_authority::OwnerControlRequest> {
            self.check()?;
            if self.phase != Phase::Imported
                || self.admission.is_some()
                || self.runtime.pending.is_some()
            {
                return Err(Error::ReviewMismatch);
            }
            stage = S::Source;
            let started = self.runtime.prepare_durable_admission_v1(EPOCH);
            attempt = self.runtime.qualification_durable_admission_attempt_v1();
            started?;
            stage = S::WorkerCompletion;
            self.drain_witness_to_review()?;
            // Counter exhaustion disables only the synthetic observation. It never
            // changes native authorization or permits an uncorrelated result.
            if attempt.is_none() {
                return Err(Error::Unavailable);
            }
            let request = match self.runtime.pending.as_ref().map(|p| &p.operation) {
                Some(Operation::DurableWitnessV1(prepared)) => match prepared.as_ref() {
                    DurableWitnessPreparedV1::Admission(admission) => admission.request().clone(),
                    _ => return Err(Error::ReviewMismatch),
                },
                _ => return Err(Error::ReviewMismatch),
            };
            stage = S::Source;
            if self
                .runtime
                .qualification_committed_durable_admission_v1()?
                .is_some()
            {
                return Err(Error::ReviewMismatch);
            }
            self.admission = Some(request.clone());
            self.phase = Phase::AdmissionPrepared;
            Ok(request)
        })();
        result.map_err(|error| {
            attempt
                .and_then(|attempt| {
                    self.runtime
                        .take_qualification_durable_admission_failure_v1(attempt)
                })
                .unwrap_or_else(|| DurableAdmissionPreparationFailureV1::new(stage, error))
        })
    }
    pub(in crate::native_ui) fn approve_durable_admission(&mut self) -> Result<()> {
        self.approve_durable_admission_inner(false)
            .map_err(DurableAdmissionDispatchFailureV1::into_error)
    }
    pub(in crate::native_ui) fn approve_durable_admission_diagnosed(
        &mut self,
    ) -> std::result::Result<(), DurableAdmissionDispatchFailureV1> {
        self.approve_durable_admission_inner(true)
    }
    /// After genuine close/open, pairing, acceptance and data-only reimport,
    /// inspect the SAME committed admission through the production historical
    /// branch. The supplied body is only an equality expectation, never an ID
    /// assignment, approval, retry, replacement admission or restored session.
    pub(in crate::native_ui) fn observe_committed_durable_admission(
        &mut self,
        expected: &wholepact_authority::OwnerControlRequest,
    ) -> std::result::Result<(), DurableAdmissionPreparationFailureV1> {
        use DurableAdmissionPreparationStageV1 as S;
        let mut stage = S::FixtureState;
        let mut attempt = None;
        let result = (|| -> Result<()> {
            self.check()?;
            let open = self.runtime.open.as_ref().ok_or(Error::Locked)?;
            if self.phase != Phase::Imported
                || self.admission.is_some()
                || self.runtime.pending.is_some()
                || open.witness_job.is_some()
                || open.writer_receipt.is_some()
                || open.writer_reconciled
                || self.reconciled_records.is_some()
                || self.reconciled_writer.is_some()
                || self.signed.is_some()
                || !matches!(
                    &expected.control,
                    wholepact_authority::OwnerControl::AdmitDurablePaymentV1 { .. }
                )
                || self
                    .runtime
                    .qualification_committed_durable_admission_v1()?
                    .is_some()
            {
                return Err(Error::ReviewMismatch);
            }
            let records = self.records()?;
            // Existing production preparation authenticates the complete original
            // witness history and exact immutable local intent. Only its historical
            // branch sets the observed ID without preparing a new native review.
            stage = S::Source;
            let started = self.runtime.prepare_durable_admission_v1(EPOCH);
            attempt = self.runtime.qualification_durable_admission_attempt_v1();
            started?;
            stage = S::WorkerCompletion;
            self.drain_witness_to_review()?;
            stage = S::RetainedIntent;
            let observed = self
                .runtime
                .qualification_committed_durable_admission_v1()?;
            let open = self.runtime.open.as_ref().ok_or(Error::Locked)?;
            require_historical_admission_observation_v1(
                expected,
                observed.as_ref(),
                self.runtime.pending.is_some(),
                open.witness_job.is_some(),
                open.writer_receipt.is_some(),
                open.writer_reconciled,
            )?;
            if self.records()? != records {
                return Err(Error::ReviewMismatch);
            }
            self.admission = observed;
            self.phase = Phase::Admitted;
            // The unchanged subsequent Session preparation rejects any already
            // recorded Acquire, pending/active session or lost original client key.
            let result = self.check();
            if result.is_ok() {
                self.observe_lifecycle_v1(
                    flow_diag_v1::DurableLifecyclePointV1::HistoricalLookupComplete,
                );
            }
            result
        })();
        result.map_err(|error| {
            attempt
                .and_then(|attempt| {
                    self.runtime
                        .take_qualification_durable_admission_failure_v1(attempt)
                })
                .unwrap_or_else(|| DurableAdmissionPreparationFailureV1::new(stage, error))
        })
    }
    fn approve_durable_admission_inner(
        &mut self,
        diagnosed: bool,
    ) -> std::result::Result<(), DurableAdmissionDispatchFailureV1> {
        // Reset inert state before this approval; exhausted counters only disable
        // optional collection and never create another operational refusal.
        self.runtime.reset_qualification_admission_dispatch_v1();
        let mut observation = DurableFixtureAdmissionObservationV1 {
            attempt: None,
            digest: None,
            stage: DurableAdmissionDispatchStageV1::FixtureState,
            original_is_operational: true,
        };
        let result = (|| {
            self.check()?;
            let expected = self
                .admission
                .as_ref()
                .ok_or(Error::ReviewMismatch)?
                .clone();
            if self.phase != Phase::AdmissionPrepared {
                return Err(Error::ReviewMismatch);
            }
            observation.stage = DurableAdmissionDispatchStageV1::ReviewCorrelation;
            match self.runtime.pending.as_ref().map(|p| &p.operation) {
                Some(Operation::DurableWitnessV1(prepared)) => match prepared.as_ref() {
                    DurableWitnessPreparedV1::Admission(admission)
                        if admission.request() == &expected => {}
                    _ => return Err(Error::ReviewMismatch),
                },
                _ => return Err(Error::ReviewMismatch),
            }
            // The unchanged native approval route retains the intent before mTLS.
            // An uncertain response cannot advance the fixture's positive path.
            observation.stage = DurableAdmissionDispatchStageV1::NativeApproval;
            self.approve_durable_and_await_inner(
                QualificationDurableWitnessCompletionV1::AdmissionCommitted,
                if diagnosed {
                    Some(&mut observation)
                } else {
                    None
                },
            )?;
            observation.stage = DurableAdmissionDispatchStageV1::CommittedCorrelation;
            if self
                .runtime
                .qualification_committed_durable_admission_v1()?
                .as_ref()
                != Some(&expected)
            {
                return Err(Error::ReviewMismatch);
            }
            self.phase = Phase::Admitted;
            self.check()
        })();
        match result {
            Ok(()) => {
                self.runtime.reset_qualification_admission_dispatch_v1();
                Ok(())
            }
            Err(error) => {
                let failure = DurableAdmissionDispatchFailureV1::new(
                    observation.stage,
                    error,
                    observation.original_is_operational,
                );
                Err(match (observation.attempt, observation.digest.as_deref()) {
                    (Some(attempt), Some(digest)) => self
                        .runtime
                        .take_qualification_admission_dispatch_v1(attempt, digest, failure),
                    _ => failure,
                })
            }
        }
    }
    fn approve_durable_and_await(
        &mut self,
        expected: QualificationDurableWitnessCompletionV1,
    ) -> Result<()> {
        self.approve_durable_and_await_inner(expected, None)
    }
    fn approve_durable_and_await_inner(
        &mut self,
        expected: QualificationDurableWitnessCompletionV1,
        mut observation: Option<&mut DurableFixtureAdmissionObservationV1>,
    ) -> Result<()> {
        let digest = self
            .runtime
            .pending
            .as_ref()
            .ok_or(Error::ReviewMismatch)?
            .review
            .digest()
            .to_owned();
        if let Some(value) = observation.as_deref_mut() {
            value.attempt = self
                .runtime
                .begin_qualification_admission_dispatch_v1(digest.clone());
            value.digest = Some(digest.clone());
        }
        let started = observation
            .as_ref()
            .filter(|value| value.attempt.is_some())
            .map(|_| Instant::now());
        let approved = approve(&mut self.runtime);
        if let Some(started) = started {
            self.runtime
                .qualification_admission_native_cost_v1(started.elapsed());
        }
        approved?;
        if let Some(value) = observation.as_deref_mut() {
            value.stage = DurableAdmissionDispatchStageV1::WorkerCompletion;
        }
        self.drain_witness_to_review()?;
        if self.runtime.pending.is_some()
            || self
                .runtime
                .qualification_durable_witness_completion_v1(&digest)
                != Some(expected)
        {
            if let Some(value) = observation.as_deref_mut() {
                value.original_is_operational = false;
                self.runtime.qualification_admission_missing_v1();
            }
            self.missing_flow_completion_v1();
            return Err(Error::Uncertain);
        }
        self.check()
    }
    fn arm_flow_v1(&mut self, operation: DurableFlowOperationV1) -> DurableFlowObservationTokenV1 {
        let observer = self
            .flow_collector
            .arm(operation)
            .with_lifecycle(self.lifecycle.as_ref());
        self.flow_observation = Some(observer.clone());
        self.flow_service = None;
        self.flow_import_expected = None;
        if let Some(open) = self.runtime.open.as_mut() {
            open.durable_witness.flow_observation = Some(observer.clone());
            open.durable_witness.flow_import = None;
        }
        DurableFlowObservationTokenV1::new(observer)
    }
    fn matching_flow_v1<'a>(
        &self,
        token: &'a DurableFlowObservationTokenV1,
    ) -> Option<&'a flow_diag_v1::DurableFlowObserverV1> {
        if self
            .flow_observation
            .as_ref()
            .is_some_and(|active| active.same_attempt(token.observer()))
        {
            Some(token.observer())
        } else {
            token.observer().mark_incomplete();
            None
        }
    }
    fn observe_fixture_result_v1<T>(
        observer: Option<&flow_diag_v1::DurableFlowObserverV1>,
        stage: DurableFlowStageV1,
        result: &Result<T>,
    ) {
        if let (Some(observer), Err(error)) = (observer, result) {
            // A typed final fixture fallback is not evidence of a worker cause.
            observer.record_terminal(stage, error);
        }
    }
    fn missing_flow_result_v1<T>(
        observer: Option<&flow_diag_v1::DurableFlowObserverV1>,
        result: Result<T>,
    ) -> Result<T> {
        if result.is_err() {
            if let Some(observer) = observer {
                observer.missing_completion();
            }
        }
        result
    }
    fn missing_flow_completion_v1(&self) {
        if let Some(observer) = &self.flow_observation {
            observer.missing_completion();
        }
    }
    fn finish_flow_v1(
        &mut self,
        token: DurableFlowObservationTokenV1,
        result: DurableFlowResultV1,
    ) -> Option<DurableFlowDiagnosticV1> {
        self.matching_flow_v1(&token)?;
        if result == DurableFlowResultV1::ReturnedErr {
            self.observe_lifecycle_once_v1(flow_diag_v1::DurableLifecyclePointV1::FixtureFailure);
        }
        if let Some(open) = self.runtime.open.as_mut() {
            if open
                .durable_witness
                .flow_observation
                .as_ref()
                .is_some_and(|active| active.same_attempt(token.observer()))
            {
                open.durable_witness.flow_observation = None;
                open.durable_witness.flow_import = None;
            }
        }
        self.flow_observation = None;
        self.flow_service = None;
        self.flow_import_expected = None;
        token.observer().finish(result)
    }
    fn acquire_source_markers_v1(&self) -> Result<[usize; 3]> {
        let open = self.runtime.open.as_ref().ok_or(Error::Locked)?;
        Ok([
            Arc::as_ptr(open.durable_born_entry.as_ref().ok_or(Error::Locked)?) as usize,
            Arc::as_ptr(open.durable_review.as_ref().ok_or(Error::Locked)?) as usize,
            Arc::as_ptr(open.session.as_ref().ok_or(Error::Locked)?) as usize,
        ])
    }
    fn require_acquire_idle_v1(&self, receipt_expected: bool) -> Result<()> {
        self.check()?;
        let open = self.runtime.open.as_ref().ok_or(Error::Locked)?;
        // Full imported-source check, not merely an inert identity comparison.
        open.durable_witness_source_v1()?.check_current()?;
        if !acquire_idle_v1([
            self.runtime.pending.is_some(),
            self.runtime.signing_job.is_some(),
            open.wallet.is_some(),
            open.wallet_job.is_some(),
            open.durable_wallet_job.is_some(),
            open.durable_import_job.is_some(),
            open.witness_job.is_some(),
            !open.revocations.is_empty(),
            open.writer_reconciled,
            open.writer_receipt.is_some() != receipt_expected,
            self.reconciled_records.is_some() || self.reconciled_writer.is_some(),
            self.signed.is_some(),
        ]) || self.admission.is_none()
            || self
                .runtime
                .qualification_committed_durable_admission_v1()?
                .as_ref()
                != self.admission.as_ref()
        {
            return Err(Error::ReviewMismatch);
        }
        Ok(())
    }
    fn require_acquire_correlation_v1(
        &self,
        correlation: &AcquireReplyLossCorrelationV1,
        receipt_expected: bool,
    ) -> Result<()> {
        self.require_acquire_idle_v1(receipt_expected)?;
        let open = self.runtime.open.as_ref().ok_or(Error::Locked)?;
        if !acquire_immutable_equal_v1(
            correlation,
            &self.entry,
            &self.records()?,
            self.acquire_source_markers_v1()?,
            &open
                .witness
                .as_ref()
                .ok_or(Error::Locked)?
                .durable_instance_v1(),
            &open
                .owner_witness
                .as_ref()
                .ok_or(Error::Locked)?
                .durable_instance_v1(),
            self.deadline()?,
            &self.signing_ledger()?,
        ) || !open.durable_witness.qualification_session_retained_v1(
            &correlation.digest,
            correlation.review_deadline,
            &correlation.history_digest,
        )? || Instant::now() >= correlation.review_deadline
        {
            return Err(Error::ReviewMismatch);
        }
        Ok(())
    }
    fn acquire_terminal_v1(
        &mut self,
        token: &DurableFlowObservationTokenV1,
        stage: DurableFlowStageV1,
        error: Error,
    ) -> DurableFlowFailureV1 {
        let failure = DurableFlowFailureV1::new_pending(error, token.observer().clone());
        // A later real source/deadline refusal may already be the terminal
        // reason. Preserve it separately from the original owned worker error;
        // do not overwrite it or mark a contradictory duplicate terminal.
        let failure = if failure
            .diagnostic()
            .is_none_or(|diagnostic| diagnostic.terminal_error().is_none())
        {
            token.observer().record_terminal(stage, failure.error());
            DurableFlowFailureV1::new_pending(failure.into_error(), token.observer().clone())
        } else {
            failure
        };
        self.observe_lifecycle_v1(flow_diag_v1::DurableLifecyclePointV1::FixtureFailure);
        self.flow_pending_drain = Some(token.observer().clone());
        failure
    }
    // Expected loss alone takes this nonterminal branch. No failure landmark,
    // ordinary pending-drain seal, reconciliation, or new native approval.
    fn finish_expected_acquire_loss_v1(
        &mut self,
        token: DurableFlowObservationTokenV1,
    ) -> Option<DurableFlowDiagnosticV1> {
        self.matching_flow_v1(&token)?;
        if let Some(open) = self.runtime.open.as_mut() {
            open.durable_witness.flow_observation = None;
            open.durable_witness.flow_import = None;
        }
        self.flow_observation = None;
        self.flow_service = None;
        self.flow_import_expected = None;
        token.observer().finish(DurableFlowResultV1::ReturnedErr)
    }
    pub(in crate::native_ui) fn acquire_original_writer_expecting_reply_loss_diagnosed(
        &mut self,
    ) -> std::result::Result<DurableAcquireReplyLossV1, DurableFlowFailureV1> {
        let token = self.arm_flow_v1(DurableFlowOperationV1::WriterReconcile);
        let mut stage = DurableFlowStageV1::FixtureState;
        let result = (|| -> Result<(AcquireReplyLossCorrelationV1, Error)> {
            self.require_acquire_idle_v1(false)?;
            let open = self.runtime.open.as_ref().ok_or(Error::Locked)?;
            if self.phase != Phase::Admitted
                || self.acquire_reply_loss.is_some()
                || !open.durable_witness.qualification_session_absent_v1()
            {
                return Err(Error::ReviewMismatch);
            }
            let mut correlation = AcquireReplyLossCorrelationV1 {
                entry: self.entry.clone(),
                records: self.records()?,
                source_markers: self.acquire_source_markers_v1()?,
                writer: open
                    .witness
                    .as_ref()
                    .ok_or(Error::Locked)?
                    .durable_instance_v1(),
                owner: open
                    .owner_witness
                    .as_ref()
                    .ok_or(Error::Locked)?
                    .durable_instance_v1(),
                deadline: self.deadline()?,
                ledger: self.signing_ledger()?,
                digest: String::new(),
                review_deadline: self.deadline()?,
                history_digest: String::new(),
                first_attempt: 0,
                retry_started: false,
            };
            stage = DurableFlowStageV1::AcquirePrepare;
            self.runtime.prepare_durable_session_v1(EPOCH)?;
            stage = DurableFlowStageV1::Completion;
            self.drain_witness_to_review()?;
            let pending = self.runtime.pending.as_ref().ok_or(Error::ReviewMismatch)?;
            let prepared = match &pending.operation {
                Operation::DurableWitnessV1(prepared) => match prepared.as_ref() {
                    DurableWitnessPreparedV1::Session(prepared) => prepared,
                    _ => return Err(Error::ReviewMismatch),
                },
                _ => return Err(Error::ReviewMismatch),
            };
            correlation.digest = pending.review.digest().to_owned();
            if correlation.digest != prepared.digest() {
                return Err(Error::ReviewMismatch);
            }
            (correlation.review_deadline, correlation.history_digest) =
                prepared.qualification_correlation_v1()?;
            self.observe_lifecycle_v1(
                flow_diag_v1::DurableLifecyclePointV1::AcquirePrepareComplete,
            );
            correlation.first_attempt = self
                .runtime
                .begin_qualification_session_v1(token.observer(), &correlation.digest)
                .ok_or(Error::Unavailable)?;
            stage = DurableFlowStageV1::AcquireNative;
            approve(&mut self.runtime)?;
            stage = DurableFlowStageV1::Completion;
            let drained = self.drain_witness_to_review();
            let actual = self.runtime.take_qualification_session_error_v1(
                correlation.first_attempt,
                &correlation.digest,
            );
            if let Err(error) = drained {
                token.observer().record_terminal(stage, &error);
                return Err(actual.unwrap_or(error));
            }
            let actual = actual.ok_or(Error::ReviewMismatch)?;
            if self
                .runtime
                .qualification_session_result_v1(correlation.first_attempt, &correlation.digest)
                != Some(false)
            {
                return Err(actual);
            }
            if let Err(error) = self.require_acquire_correlation_v1(&correlation, false) {
                token
                    .observer()
                    .record_terminal(DurableFlowStageV1::FixtureState, &error);
                return Err(actual);
            }
            Ok((correlation, actual))
        })();
        let (correlation, actual) = match result {
            Ok(value) => value,
            Err(error) => return Err(self.acquire_terminal_v1(&token, stage, error)),
        };
        let observed = DurableFlowFailureV1::new_pending(actual, token.observer().clone());
        if !observed
            .diagnostic()
            .is_some_and(|diagnostic| acquire_loss_diagnostic_v1(observed.error(), diagnostic))
        {
            return Err(self.acquire_terminal_v1(&token, stage, observed.into_error()));
        }
        let observer = token.observer().clone();
        let Some(diagnostic) = self.finish_expected_acquire_loss_v1(token) else {
            self.observe_lifecycle_v1(flow_diag_v1::DurableLifecyclePointV1::FixtureFailure);
            self.flow_pending_drain = Some(observer.clone());
            return Err(DurableFlowFailureV1::new_pending(
                observed.into_error(),
                observer,
            ));
        };
        let result = DurableAcquireReplyLossV1 {
            error: observed.into_error(),
            diagnostic,
        };
        if !result.is_expected_loss() {
            return Err(DurableFlowFailureV1::new(
                result.error,
                Some(result.diagnostic),
            ));
        }
        self.acquire_reply_loss = Some(correlation);
        self.phase = Phase::AcquireReplyLost;
        Ok(result)
    }
    pub(in crate::native_ui) fn retry_original_writer_after_reply_loss_diagnosed(
        &mut self,
    ) -> std::result::Result<wholepact_authority::WriterSessionReceipt, DurableFlowFailureV1> {
        let token = self.arm_flow_v1(DurableFlowOperationV1::WriterReconcile);
        let mut stage = DurableFlowStageV1::FixtureState;
        let result = (|| -> Result<wholepact_authority::WriterSessionReceipt> {
            let correlation = self
                .acquire_reply_loss
                .as_ref()
                .ok_or(Error::ReviewMismatch)?;
            if !acquire_retry_phase_v1(self.phase, correlation.retry_started) {
                return Err(Error::ReviewMismatch);
            }
            self.require_acquire_correlation_v1(correlation, false)?;
            let digest = correlation.digest.clone();
            let first_attempt = correlation.first_attempt;
            let attempt = self
                .runtime
                .begin_qualification_session_v1(token.observer(), &digest)
                .ok_or(Error::Unavailable)?;
            if attempt == first_attempt {
                return Err(Error::ReviewMismatch);
            }
            self.acquire_reply_loss
                .as_mut()
                .ok_or(Error::ReviewMismatch)?
                .retry_started = true;
            stage = DurableFlowStageV1::AcquireCall;
            // The sole retry entry point. It clones the original approved Arc and
            // the same workspace/client; no prepare/approval/reentry is involved.
            self.runtime.retry_durable_witness_v1(1, EPOCH)?;
            stage = DurableFlowStageV1::Completion;
            let drained = self.drain_witness_to_review();
            let actual = self
                .runtime
                .take_qualification_session_error_v1(attempt, &digest);
            if let Err(error) = drained {
                token.observer().record_terminal(stage, &error);
                return Err(actual.unwrap_or(error));
            }
            if let Some(error) = actual {
                return Err(error);
            }
            if self
                .runtime
                .qualification_session_result_v1(attempt, &digest)
                != Some(true)
                || self
                    .runtime
                    .qualification_durable_witness_completion_v1(&digest)
                    != Some(QualificationDurableWitnessCompletionV1::SessionAcquired)
            {
                self.missing_flow_completion_v1();
                return Err(Error::ReviewMismatch);
            }
            self.require_acquire_correlation_v1(
                self.acquire_reply_loss
                    .as_ref()
                    .ok_or(Error::ReviewMismatch)?,
                true,
            )?;
            let receipt = self
                .runtime
                .open
                .as_ref()
                .ok_or(Error::Locked)?
                .writer_receipt
                .as_ref()
                .ok_or(Error::ReviewMismatch)?
                .clone();
            self.phase = Phase::AcquireRetriedPending;
            Ok(receipt)
        })();
        match result {
            Ok(receipt) => {
                self.finish_flow_v1(token, DurableFlowResultV1::ReturnedOk);
                Ok(receipt)
            }
            Err(error) => Err(self.acquire_terminal_v1(&token, stage, error)),
        }
    }
    pub(in crate::native_ui) fn reconcile_original_writer_diagnosed(
        &mut self,
    ) -> std::result::Result<(), DurableFlowFailureV1> {
        let token = self.arm_flow_v1(DurableFlowOperationV1::WriterReconcile);
        let mut stage = DurableFlowStageV1::FixtureState;
        let result = self.reconcile_original_writer_inner(&mut stage);
        Self::observe_fixture_result_v1(Some(token.observer()), stage, &result);
        match result {
            Ok(()) => {
                self.finish_flow_v1(token, DurableFlowResultV1::ReturnedOk);
                Ok(())
            }
            Err(error) => {
                // Preserve the initial failure and this exact inert observer
                // until Drop performs its already-required single owner drain.
                // No retry, fresh owner or additional operational check occurs.
                self.observe_lifecycle_v1(flow_diag_v1::DurableLifecyclePointV1::FixtureFailure);
                self.flow_pending_drain = Some(token.observer().clone());
                Err(DurableFlowFailureV1::new_pending(
                    error,
                    token.observer().clone(),
                ))
            }
        }
    }
    pub(in crate::native_ui) fn reconcile_original_writer(&mut self) -> Result<()> {
        self.reconcile_original_writer_inner(&mut DurableFlowStageV1::FixtureState)
    }
    fn reconcile_original_writer_inner(&mut self, stage: &mut DurableFlowStageV1) -> Result<()> {
        let observation = self.flow_observation.clone();
        flow_diag_v1::observe_result(
            observation.as_ref(),
            DurableFlowStageV1::FixtureState,
            self.check(),
        )?;
        if self.phase != Phase::Admitted
            || self.runtime.pending.is_some()
            || self
                .runtime
                .qualification_committed_durable_admission_v1()?
                .as_ref()
                != self.admission.as_ref()
        {
            return Err(Error::ReviewMismatch);
        }
        let old_records = self.records()?;
        let open = self.runtime.open.as_ref().ok_or(Error::Locked)?;
        let writer = open.witness.as_ref().ok_or(Error::Locked)?.clone();
        let owner = open.owner_witness.as_ref().ok_or(Error::Locked)?.clone();
        if open.writer_receipt.is_some() || open.writer_reconciled {
            return Err(Error::ReviewMismatch);
        }
        *stage = DurableFlowStageV1::AcquirePrepare;
        flow_diag_v1::observe_result(
            observation.as_ref(),
            DurableFlowStageV1::AcquirePrepare,
            self.runtime.prepare_durable_session_v1(EPOCH),
        )?;
        *stage = DurableFlowStageV1::Completion;
        self.drain_witness_to_review()?;
        if !matches!(
            self.runtime.pending.as_ref().map(|p| &p.operation),
            Some(Operation::DurableWitnessV1(prepared))
                if matches!(prepared.as_ref(), DurableWitnessPreparedV1::Session(_))
        ) {
            self.missing_flow_completion_v1();
            return Err(Error::ReviewMismatch);
        }
        self.observe_lifecycle_v1(flow_diag_v1::DurableLifecyclePointV1::AcquirePrepareComplete);
        *stage = DurableFlowStageV1::Completion;
        self.approve_durable_and_await(QualificationDurableWitnessCompletionV1::SessionAcquired)?;
        let receipt = self
            .runtime
            .open
            .as_ref()
            .ok_or(Error::Locked)?
            .writer_receipt
            .as_ref()
            .ok_or(Error::ReviewMismatch)?
            .clone();
        *stage = DurableFlowStageV1::ActivationPrepare;
        flow_diag_v1::observe_result(
            observation.as_ref(),
            DurableFlowStageV1::ActivationPrepare,
            self.runtime.prepare_durable_activation_v1(EPOCH),
        )?;
        *stage = DurableFlowStageV1::Completion;
        self.drain_witness_to_review()?;
        if !matches!(
            self.runtime.pending.as_ref().map(|p| &p.operation),
            Some(Operation::DurableWitnessV1(prepared))
                if matches!(prepared.as_ref(), DurableWitnessPreparedV1::Activation(_))
        ) {
            self.missing_flow_completion_v1();
            return Err(Error::ReviewMismatch);
        }
        *stage = DurableFlowStageV1::Completion;
        self.approve_durable_and_await(
            QualificationDurableWitnessCompletionV1::ActivationCommitted,
        )?;
        *stage = DurableFlowStageV1::ReconcilePrepare;
        flow_diag_v1::observe_result(
            observation.as_ref(),
            DurableFlowStageV1::ReconcilePrepare,
            self.runtime.prepare_durable_reconciliation_v1(EPOCH),
        )?;
        *stage = DurableFlowStageV1::Completion;
        self.drain_witness_to_review()?;
        if !matches!(
            self.runtime.pending.as_ref().map(|p| &p.operation),
            Some(Operation::DurableWitnessV1(prepared))
                if matches!(prepared.as_ref(), DurableWitnessPreparedV1::Reconciliation(_))
        ) {
            self.missing_flow_completion_v1();
            return Err(Error::ReviewMismatch);
        }
        *stage = DurableFlowStageV1::Completion;
        self.approve_durable_and_await(
            QualificationDurableWitnessCompletionV1::ReconciliationCommitted,
        )?;
        *stage = DurableFlowStageV1::Completion;
        // Observe actual invalidation and drain without rescanning the full
        // journal on each pending redraw. The original owned polling refusal
        // returns unchanged, and success still crosses the full exit gate.
        {
            let mut waiting = (&mut *self, None::<Error>);
            witness_wait_v1::run(
                &mut waiting,
                |(fixture, _)| fixture.pending_wait_full_entry_v1(),
                |(fixture, _)| fixture.pending_wait_live_v1(),
                |(fixture, failure)| {
                    fixture.measure_pending_wait_v1(
                        flow_diag_v1::DurablePendingWaitKindV1::Poll,
                        |fixture| {
                            fixture.runtime.poll(EPOCH);
                            match fixture.runtime.open.as_ref() {
                                Some(open) => open.revocations.is_empty(),
                                None => {
                                    *failure = Some(Error::Locked);
                                    true
                                }
                            }
                        },
                    )
                },
                |(fixture, failure)| {
                    if let Some(original) = failure.take() {
                        return Err(original);
                    }
                    fixture.pending_wait_full_exit_v1()
                },
                |_| std::thread::sleep(Duration::from_millis(2)),
            )?;
        }
        let open = self.runtime.open.as_ref().ok_or(Error::Locked)?;
        if open.session.is_some()
            || open.enrollment.is_some()
            || open.manifest.is_some()
            || open.durable_review.is_some()
            || open.durable_import_job.is_some()
            || open.durable_wallet_job.is_some()
            || open.witness_job.is_some()
            || !open.writer_reconciled
            || self.runtime.pending.is_some()
            || !Arc::ptr_eq(open.witness.as_ref().ok_or(Error::Locked)?, &writer)
            || !Arc::ptr_eq(open.owner_witness.as_ref().ok_or(Error::Locked)?, &owner)
            || open.writer_receipt.as_ref() != Some(&receipt)
        {
            return Err(Error::ReviewMismatch);
        }
        self.reconciled_records = Some(old_records);
        self.reconciled_writer = Some((writer.durable_instance_v1(), receipt));
        self.expected = None;
        // This phase change is allowed only after the observations above. The
        // subsequent acceptance still invokes the genuine fresh native route.
        self.phase = Phase::Paired;
        self.observe_lifecycle_once_v1(
            flow_diag_v1::DurableLifecyclePointV1::WriterReconcileComplete,
        );
        Ok(())
    }
    fn drain_witness_to_review(&mut self) -> Result<()> {
        let job = self
            .runtime
            .open
            .as_ref()
            .ok_or(Error::Locked)?
            .witness_job
            .as_ref()
            .ok_or(Error::ReviewMismatch);
        let done = Self::missing_flow_result_v1(self.flow_observation.as_ref(), job)?
            .done
            .clone();
        let lifecycle = self.lifecycle.clone();
        witness_wait_v1::run(
            self,
            |fixture| {
                flow_diag_v1::observe_pending_wait_v1(
                    lifecycle.as_ref(),
                    flow_diag_v1::DurablePendingWaitKindV1::FullPrecheck,
                    || fixture.check(),
                )
            },
            |fixture| {
                flow_diag_v1::observe_pending_wait_v1(
                    lifecycle.as_ref(),
                    flow_diag_v1::DurablePendingWaitKindV1::Liveness,
                    || fixture.check_pending_witness_v1(),
                )
            },
            |fixture| {
                flow_diag_v1::observe_pending_wait_v1(
                    lifecycle.as_ref(),
                    flow_diag_v1::DurablePendingWaitKindV1::Poll,
                    || {
                        // The production receive gate and worker checks are unchanged.
                        // The original done flag must still observe this worker's exit.
                        fixture.runtime.poll_witness(EPOCH);
                        fixture
                            .runtime
                            .open
                            .as_ref()
                            .is_none_or(|o| o.witness_job.is_none())
                            && done.load(Ordering::Acquire)
                    },
                )
            },
            |fixture| {
                flow_diag_v1::observe_pending_wait_v1(
                    lifecycle.as_ref(),
                    flow_diag_v1::DurablePendingWaitKindV1::FullPostcheck,
                    || fixture.check(),
                )
            },
            |_| std::thread::sleep(Duration::from_millis(2)),
        )
    }
    // Pending-only fixture liveness, never a current-source or journal grant.
    // Full original-source checks surround the wait; workers and the production
    // received-result gate retain their complete current-source validation.
    fn check_pending_witness_v1(&self) -> Result<()> {
        let original = self.original.as_ref().ok_or(Error::Locked)?;
        let open = self.runtime.open.as_ref().ok_or(Error::Locked)?;
        let source = open.durable_born_entry.as_ref().ok_or(Error::Locked)?;
        flow_diag_v1::observe_result(
            self.flow_observation.as_ref(),
            DurableFlowStageV1::FixtureState,
            source.native_owner().check_current(),
        )?;
        flow_diag_v1::observe_result(
            self.flow_observation.as_ref(),
            DurableFlowStageV1::FixtureState,
            open.pairing.as_ref().ok_or(Error::Locked)?.check_current(),
        )?;
        if flow_diag_v1::observe_result(
            self.flow_observation.as_ref(),
            DurableFlowStageV1::FixtureState,
            open.vault.account_id(),
        )? != original.account_id
            || open.authority.binding().entry_digest() != self.entry
            || open.authority.binding() != source.native_binding()
        {
            return Err(Error::ReviewMismatch);
        }
        Ok(())
    }
    /// Called after each host IPC boundary while no approval is pending. Import
    /// success is still data-only: this method never starts financial review.
    pub(in crate::native_ui) fn poll_data_only(&mut self) -> Result<()> {
        self.check()?;
        self.runtime.poll(EPOCH);
        self.runtime.poll_durable_import_v1(EPOCH);
        if self.runtime.pending.is_some() {
            return Err(Error::ReviewMismatch);
        }
        self.check()
    }
    /// Imported is private memory only. It neither persists remote material nor
    /// starts a wallet review, financial decision, writer or signing operation.
    pub(in crate::native_ui) fn poll_exact_import(
        &mut self,
        request: &DurableReviewDeliveryRequestV1,
        identity: &wholepact_protocol::durable_proposal_v1::FixedProposalIdentityV1,
    ) -> Result<bool> {
        self.poll_data_only()?;
        if !matches!(self.phase, Phase::Disclosed | Phase::Imported) {
            return Err(Error::ReviewMismatch);
        }
        let open = self.runtime.open.as_ref().ok_or(Error::Locked)?;
        if open.writer_reconciled
            || open.writer_receipt.is_some()
            || open.durable_wallet_job.is_some()
            || self.runtime.signing_job.is_some()
        {
            return Err(Error::ReviewMismatch);
        }
        let Some(imported) = &open.durable_review else {
            return Ok(false);
        };
        if &imported.request != request || imported.fixed.verified().identity() != identity {
            return Err(Error::ReviewMismatch);
        }
        self.phase = Phase::Imported;
        self.observe_lifecycle_v1(flow_diag_v1::DurableLifecyclePointV1::ImportComplete);
        Ok(true)
    }

    /// Financial import has its own restrictive phase; it does not relax the
    /// import-only baseline's explicit prohibition on writer reconciliation.
    pub(in crate::native_ui) fn poll_financial_import(
        &mut self,
        request: &DurableReviewDeliveryRequestV1,
        identity: &FixedProposalIdentityV1,
    ) -> Result<bool> {
        self.poll_data_only()?;
        if !matches!(self.phase, Phase::Disclosed | Phase::FinancialImported) {
            return Err(Error::ReviewMismatch);
        }
        let open = self.runtime.open.as_ref().ok_or(Error::Locked)?;
        if !open.writer_reconciled
            || open.writer_receipt.is_none()
            || open.wallet.is_none()
            || open.wallet_job.is_some()
            || open.durable_wallet_job.is_some()
            || self.runtime.signing_job.is_some()
            || !open.revocations.is_empty()
        {
            return Err(Error::ReviewMismatch);
        }
        flow_diag_v1::observe_result(
            self.flow_observation.as_ref(),
            DurableFlowStageV1::WalletSource,
            open.wallet.as_ref().ok_or(Error::Locked)?.check_current(),
        )?;
        let Some(imported) = &open.durable_review else {
            return Ok(false);
        };
        if &imported.request != request || imported.fixed.verified().identity() != identity {
            return Err(Error::ReviewMismatch);
        }
        let records = self.records()?;
        if request.enrollment_ref != records.enrollment_ref
            || request.accepted_manifest_ref != records.accepted_manifest_ref
        {
            return Err(Error::ReviewMismatch);
        }
        self.phase = Phase::FinancialImported;
        Ok(true)
    }

    pub(in crate::native_ui) fn begin_financial_import_wait_diagnosed<'a>(
        &'a mut self,
        token: &'a DurableFlowObservationTokenV1,
        request: &'a DurableReviewDeliveryRequestV1,
        identity: &'a FixedProposalIdentityV1,
    ) -> Result<DurableFinancialImportWaitV1<'a>> {
        let (state, deadline) = witness_wait_v1::begin(self, |fixture| {
            fixture.measure_pending_wait_v1(
                flow_diag_v1::DurablePendingWaitKindV1::FullPrecheck,
                |fixture| fixture.financial_import_deadline_diagnosed(token),
            )
        })?;
        Ok(DurableFinancialImportWaitV1 {
            fixture: self,
            token,
            request,
            identity,
            deadline,
            state,
        })
    }
    fn poll_financial_import_pending_v1(
        &mut self,
        request: &DurableReviewDeliveryRequestV1,
        identity: &FixedProposalIdentityV1,
    ) -> Result<bool> {
        self.runtime.poll(EPOCH);
        self.runtime.poll_durable_import_v1(EPOCH);
        if self.runtime.pending.is_some() {
            return Err(Error::ReviewMismatch);
        }
        if !matches!(self.phase, Phase::Disclosed | Phase::FinancialImported) {
            return Err(Error::ReviewMismatch);
        }
        let open = self.runtime.open.as_ref().ok_or(Error::Locked)?;
        if !open.writer_reconciled
            || open.writer_receipt.is_none()
            || open.wallet.is_none()
            || open.wallet_job.is_some()
            || open.durable_wallet_job.is_some()
            || self.runtime.signing_job.is_some()
            || !open.revocations.is_empty()
        {
            return Err(Error::ReviewMismatch);
        }
        flow_diag_v1::observe_result(
            self.flow_observation.as_ref(),
            DurableFlowStageV1::WalletSource,
            open.wallet.as_ref().ok_or(Error::Locked)?.check_current(),
        )?;
        let Some(imported) = &open.durable_review else {
            return Ok(false);
        };
        if &imported.request != request || imported.fixed.verified().identity() != identity {
            return Err(Error::ReviewMismatch);
        }
        Ok(true)
    }

    pub(in crate::native_ui) fn arm_financial_import_diagnostics(
        &mut self,
        request: &DurableReviewDeliveryRequestV1,
        identity: &FixedProposalIdentityV1,
    ) -> DurableFlowObservationTokenV1 {
        let token = self.arm_flow_v1(DurableFlowOperationV1::FinancialImport);
        if let Some(open) = self.runtime.open.as_mut() {
            if open.durable_import_job.is_some() || open.durable_review.is_some() {
                token.observer().mark_incomplete();
            } else {
                let expected = super::durable_review_v1::DurableFlowImportExpectationV1::new(
                    request,
                    identity,
                    EPOCH,
                    token.observer(),
                );
                self.flow_import_expected = expected.clone();
                open.durable_witness.flow_import = expected;
            }
        } else {
            token.observer().mark_incomplete();
        }
        token
    }
    pub(in crate::native_ui) fn financial_import_deadline_diagnosed(
        &self,
        token: &DurableFlowObservationTokenV1,
    ) -> Result<Instant> {
        let result = flow_diag_v1::observe_result(
            self.matching_flow_v1(token),
            DurableFlowStageV1::FixtureState,
            self.deadline(),
        );
        Self::observe_fixture_result_v1(
            self.matching_flow_v1(token),
            DurableFlowStageV1::FixtureState,
            &result,
        );
        result
    }
    pub(in crate::native_ui) fn poll_financial_import_diagnosed(
        &mut self,
        token: &DurableFlowObservationTokenV1,
        request: &DurableReviewDeliveryRequestV1,
        identity: &FixedProposalIdentityV1,
    ) -> Result<bool> {
        // Ordinary runtime polls may already have consumed this same real job.
        // No poll arms, replaces, finishes, or takes its diagnostic attempt.
        if self.matching_flow_v1(token).is_some()
            && self
                .flow_import_expected
                .as_ref()
                .is_none_or(|expected| !expected.matches_poll(request, identity, EPOCH))
        {
            token.observer().mark_incomplete();
        }
        let result = self.poll_financial_import(request, identity);
        Self::observe_fixture_result_v1(
            self.matching_flow_v1(token),
            DurableFlowStageV1::FixtureState,
            &result,
        );
        result
    }
    pub(in crate::native_ui) fn finish_financial_import_diagnostics(
        &mut self,
        token: DurableFlowObservationTokenV1,
        result: DurableFlowResultV1,
    ) -> Option<DurableFlowDiagnosticV1> {
        self.finish_flow_v1(token, result)
    }
    pub(in crate::native_ui) fn arm_result_service_diagnostics(
        &mut self,
    ) -> DurableFlowObservationTokenV1 {
        let token = self.arm_flow_v1(DurableFlowOperationV1::ResultService);
        self.flow_service = Some(
            token
                .observer()
                .job_start(flow_diag_v1::DurableFlowJobPurposeV1::ResultService, EPOCH),
        );
        token
    }
    pub(in crate::native_ui) fn result_service_deadline_diagnosed(
        &self,
        token: &DurableFlowObservationTokenV1,
    ) -> Result<Instant> {
        let result = flow_diag_v1::observe_result(
            self.matching_flow_v1(token),
            DurableFlowStageV1::ResultService,
            self.deadline(),
        );
        Self::observe_fixture_result_v1(
            self.matching_flow_v1(token),
            DurableFlowStageV1::ResultService,
            &result,
        );
        result
    }
    pub(in crate::native_ui) fn poll_result_service_diagnosed(
        &mut self,
        token: &DurableFlowObservationTokenV1,
    ) -> Result<()> {
        let result = self.poll_data_only();
        let result = flow_diag_v1::observe_result(
            self.matching_flow_v1(token),
            DurableFlowStageV1::ResultService,
            result,
        );
        Self::observe_fixture_result_v1(
            self.matching_flow_v1(token),
            DurableFlowStageV1::ResultService,
            &result,
        );
        result
    }
    pub(in crate::native_ui) fn finish_result_service_diagnostics(
        &mut self,
        token: DurableFlowObservationTokenV1,
        result: DurableFlowResultV1,
    ) -> Option<DurableFlowDiagnosticV1> {
        if self.matching_flow_v1(&token).is_some() {
            if let Some(job) = &self.flow_service {
                job.completed(result);
            }
        }
        self.finish_flow_v1(token, result)
    }

    fn signing_ledger(&self) -> Result<Vec<(u64, [u8; 32])>> {
        self.check()?;
        let open = self.runtime.open.as_ref().ok_or(Error::Locked)?;
        let snapshot = open
            .journal
            .qualification_durable_ledger_v1(open.session.as_deref().ok_or(Error::Locked)?)?;
        self.check()?;
        Ok(snapshot)
    }
    fn require_idle_financial_state(&self, identity: &FixedProposalIdentityV1) -> Result<()> {
        self.check()?;
        let open = self.runtime.open.as_ref().ok_or(Error::Locked)?;
        let (instance, receipt) = self
            .reconciled_writer
            .as_ref()
            .ok_or(Error::ReviewMismatch)?;
        open.witness
            .as_ref()
            .ok_or(Error::Locked)?
            .require_durable_instance_v1(instance)?;
        if self.runtime.pending.is_some()
            || self.runtime.signing_job.is_some()
            || open.wallet_job.is_some()
            || open.durable_wallet_job.is_some()
            || open.durable_import_job.is_some()
            || open.witness_job.is_some()
            || !open.revocations.is_empty()
            || !open.writer_reconciled
            || open.writer_receipt.is_none()
            || open.writer_receipt.as_ref() != Some(receipt)
            || open.wallet.is_none()
            || open
                .durable_review
                .as_ref()
                .is_none_or(|i| i.fixed.verified().identity() != identity)
        {
            return Err(Error::ReviewMismatch);
        }
        Ok(())
    }
    pub(in crate::native_ui) fn sign_durable_fixed_diagnosed(
        &mut self,
        identity: &FixedProposalIdentityV1,
    ) -> std::result::Result<(HistoryRequest, AuthorizationCommit), DurableFlowFailureV1> {
        let operation = if self.signed.is_some() {
            DurableFlowOperationV1::RetainedRetry
        } else {
            DurableFlowOperationV1::InitialSign
        };
        let token = self.arm_flow_v1(operation);
        let mut stage = DurableFlowStageV1::FixtureState;
        let result = self.sign_durable_fixed_inner(identity, &mut stage);
        Self::observe_fixture_result_v1(Some(token.observer()), stage, &result);
        let diagnostic = self.finish_flow_v1(
            token,
            if result.is_ok() {
                DurableFlowResultV1::ReturnedOk
            } else {
                DurableFlowResultV1::ReturnedErr
            },
        );
        result.map_err(|error| DurableFlowFailureV1::new(error, diagnostic))
    }
    pub(in crate::native_ui) fn sign_durable_fixed(
        &mut self,
        identity: &FixedProposalIdentityV1,
    ) -> Result<(HistoryRequest, AuthorizationCommit)> {
        self.sign_durable_fixed_inner(identity, &mut DurableFlowStageV1::FixtureState)
    }
    fn sign_durable_fixed_inner(
        &mut self,
        identity: &FixedProposalIdentityV1,
        stage: &mut DurableFlowStageV1,
    ) -> Result<(HistoryRequest, AuthorizationCommit)> {
        let observation = self.flow_observation.clone();
        flow_diag_v1::observe_result(
            observation.as_ref(),
            DurableFlowStageV1::FixtureState,
            self.require_idle_financial_state(identity),
        )?;
        if !matches!(self.phase, Phase::FinancialImported | Phase::Signed) {
            return Err(Error::ReviewMismatch);
        }
        let before = self.signing_ledger()?;
        if let Some((history, commit, retained_ledger)) = &self.signed {
            *stage = DurableFlowStageV1::RetryInvariant;
            if self.phase != Phase::Signed || retained_ledger != &before {
                return Err(Error::ReviewMismatch);
            }
            let expected = (history.clone(), commit.clone());
            let wallet_owner = self
                .runtime
                .open
                .as_ref()
                .ok_or(Error::Locked)?
                .wallet
                .as_ref()
                .ok_or(Error::Locked)?
                .revoke_handle();
            // Invoke the REAL production retry entry point, not a fixture
            // short-circuit. It must return synchronously without staging any
            // review or job; every authority-ledger row must remain identical.
            *stage = DurableFlowStageV1::RetainedLookup;
            self.runtime.start_durable_wallet_review_v1(EPOCH)?;
            self.require_idle_financial_state(identity)?;
            let wallet_after = self
                .runtime
                .open
                .as_ref()
                .ok_or(Error::Locked)?
                .wallet
                .as_ref()
                .ok_or(Error::Locked)?
                .revoke_handle();
            let actual = self
                .runtime
                .qualification_retained_durable_result_v1(identity)?
                .ok_or(Error::RecoveryRequired)?;
            if actual != expected
                || !wallet_owner.same_origin(&wallet_after)
                || self.signing_ledger()? != before
                || self.runtime.last_receipt.as_deref()
                    != Some(actual.1.original_consent_ref.as_str())
            {
                return Err(Error::ReviewMismatch);
            }
            return Ok(actual);
        }
        if self.phase != Phase::FinancialImported
            || before.len() != 14
            || before[13].0 != 1
            || before[..7].iter().any(|(count, _)| *count != 0)
            || self
                .runtime
                .qualification_retained_durable_result_v1(identity)?
                .is_some()
        {
            return Err(Error::ReviewMismatch);
        }
        let deadline = self.deadline()?;
        *stage = DurableFlowStageV1::WalletSync;
        self.runtime.start_durable_wallet_review_v1(EPOCH)?;
        *stage = DurableFlowStageV1::Completion;
        if self
            .runtime
            .open
            .as_ref()
            .is_none_or(|o| o.durable_wallet_job.is_none())
        {
            self.missing_flow_completion_v1();
            return Err(Error::ReviewMismatch);
        }
        witness_wait_v1::run(
            self,
            |fixture| fixture.pending_wait_full_entry_v1(),
            |fixture| fixture.pending_wait_live_v1(),
            |fixture| {
                fixture.measure_pending_wait_v1(
                    flow_diag_v1::DurablePendingWaitKindV1::Poll,
                    |fixture| {
                        fixture.runtime.poll(EPOCH);
                        fixture.runtime.poll_durable_wallet_review_v1(EPOCH);
                        fixture
                            .runtime
                            .open
                            .as_ref()
                            .is_none_or(|open| open.durable_wallet_job.is_none())
                    },
                )
            },
            |fixture| fixture.pending_wait_full_exit_v1(),
            |_| std::thread::sleep(Duration::from_millis(2)),
        )?;
        *stage = DurableFlowStageV1::Completion;
        let history = match self.runtime.pending.as_ref().map(|p| &p.operation) {
            Some(Operation::DurableDisclosureV1 { flow, .. })
                if flow.qualification_identity() == identity =>
            {
                flow.qualification_history()
            }
            _ => {
                self.missing_flow_completion_v1();
                return Err(Error::ReviewMismatch);
            }
        };
        let records = self.records()?;
        if history.expected_enrollment_ref != records.enrollment_ref
            || history.expected_manifest_ref != records.accepted_manifest_ref
        {
            return Err(Error::ReviewMismatch);
        }
        *stage = DurableFlowStageV1::DisclosureDecision;
        approve(&mut self.runtime)?;
        *stage = DurableFlowStageV1::Completion;
        match self.runtime.pending.as_ref().map(|p| &p.operation) {
            Some(Operation::DurableSpendV1 { flow, .. })
                if flow.qualification_identity() == identity
                    && flow.qualification_history() == history => {}
            _ => {
                self.missing_flow_completion_v1();
                return Err(Error::ReviewMismatch);
            }
        }
        *stage = DurableFlowStageV1::SpendDecision;
        approve(&mut self.runtime)?;
        *stage = DurableFlowStageV1::Completion;
        if self.runtime.signing_job.is_none() || self.runtime.open.is_some() {
            self.missing_flow_completion_v1();
            return Err(Error::ReviewMismatch);
        }
        *stage = DurableFlowStageV1::Completion;
        // During signing the genuine worker owns OpenAccount. Keep the same
        // original deadline and peer checks; never synthesize another owner.
        while self.runtime.signing_job.is_some() {
            if Instant::now() >= deadline {
                return Err(Error::ReviewMismatch);
            }
            self.runtime.poll_signing();
            std::thread::sleep(Duration::from_millis(2));
        }
        self.require_idle_financial_state(identity)?;
        let actual = self
            .runtime
            .qualification_retained_durable_result_v1(identity)?
            .ok_or(Error::RecoveryRequired)?;
        let after = self.signing_ledger()?;
        let own_inputs = self
            .proposal
            .manifest()
            .inputs
            .iter()
            .filter(|input| input.account_id == self.scope.account_id)
            .count() as u64;
        if actual.0 != history
            || !actual.1.exposure_remains_uncertain
            || self.runtime.last_receipt.as_deref() != Some(actual.1.original_consent_ref.as_str())
            || after.len() != before.len()
            || own_inputs == 0
            || after[..7]
                .iter()
                .enumerate()
                .any(|(index, (count, _))| *count != if index == 2 { own_inputs } else { 1 })
            || after[7..] != before[7..]
        {
            return Err(Error::ReviewMismatch);
        }
        self.signed = Some((actual.0.clone(), actual.1.clone(), after));
        self.phase = Phase::Signed;
        self.observe_lifecycle_once_v1(flow_diag_v1::DurableLifecyclePointV1::InitialSignComplete);
        Ok(actual)
    }
    pub(in crate::native_ui) fn close(mut self) -> Result<AcknowledgedBornFixture> {
        self.drain_close()?;
        let original = self.original.as_ref().ok_or(Error::Locked)?;
        if original_inventory(&original.root)? != self.original_inventory {
            return Err(Error::ReviewMismatch);
        }
        self.original.take().ok_or(Error::Locked)
    }
    fn drain_close(&mut self) -> Result<()> {
        self.runtime.lock();
        // Finishing a previously admitted operation is not permission renewal.
        // Keep the real account directory and original witness fixture alive
        // until every close completion says the owner actually terminated.
        while self.runtime.signing_job.is_some() || !self.runtime.closing_accounts.is_empty() {
            self.runtime.poll_signing();
            self.runtime
                .closing_accounts
                .retain(|done| !done.load(Ordering::Acquire));
            std::thread::sleep(Duration::from_millis(2));
        }
        if self.runtime.open.is_some()
            || self.runtime.pending.is_some()
            || self.runtime.durable_entry_job.is_some()
        {
            return Err(Error::Uncertain);
        }
        Ok(())
    }
}

fn original_inventory(root: &Path) -> Result<BTreeSet<OsString>> {
    let mut inventory = BTreeSet::new();
    for entry in std::fs::read_dir(root)? {
        let entry = entry?;
        if !std::fs::symlink_metadata(entry.path())?.is_file()
            || !inventory.insert(entry.file_name())
            || inventory.len() > 128
        {
            return Err(Error::InvalidData);
        }
    }
    Ok(inventory)
}
impl Drop for DurableNativeFixtureV1 {
    fn drop(&mut self) {
        let result = self.drain_close();
        if let Some(observer) = self.flow_pending_drain.as_ref() {
            self.observe_lifecycle_v1(flow_diag_v1::DurableLifecyclePointV1::AfterDrain);
            observer.record_drain(&result);
        }
    }
}

fn approve(runtime: &mut NativeRuntime) -> Result<()> {
    let pending = runtime.pending.as_mut().ok_or(Error::ReviewMismatch)?;
    if pending.review.display().is_empty()
        || pending.review.confirming()
        || pending
            .review
            .continue_from_native_click(false, EPOCH)
            .is_ok()
        || pending
            .review
            .continue_from_native_click(true, EPOCH + 1)
            .is_ok()
    {
        return Err(Error::ReviewMismatch);
    }
    pending.review.continue_from_native_click(true, EPOCH)?;
    runtime.confirmation = Zeroizing::new(format!("AUTHORIZE {}", &pending.review.digest()[..12]));
    runtime.approve(true, EPOCH)
}

fn require_plain_two_owner_manifest(proposal: &Proposal, own: &str) -> Result<()> {
    let m = proposal.manifest();
    if m.participants.len() != 2
        || m.agreement.recipients.len() != 1
        || !m.agreement.extensions.is_empty()
        || m.participants.iter().any(|p| !p.charges.is_empty())
        || !m.participants.iter().any(|p| p.account_id == own)
        || m.participants[0].account_id == m.participants[1].account_id
        || m.participants.iter().any(|p| {
            p.account_id.len() != 64
                || !p
                    .account_id
                    .bytes()
                    .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c))
        })
    {
        return Err(Error::ReviewMismatch);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    // Equality-only data. This constructs no native owner, authenticated
    // history, retained intent, decision, admission or signing capability.
    fn historical_admission_data() -> wholepact_authority::OwnerControlRequest {
        use wholepact_authority::durable_payment_v1::{
            DurableFixedCandidateBindingV1, DurablePaymentAdmissionRecordV1,
            DurablePaymentAdmissionTermsV1,
        };
        wholepact_authority::OwnerControlRequest {
            operation_id: "inert-original-admission".into(),
            account_id: "11".repeat(32),
            network_profile_id: "inert-network".into(),
            writer_epoch: 1,
            expected_head: wholepact_authority::AuthorityHead {
                sequence: 4,
                digest: "12".repeat(32),
            },
            control: wholepact_authority::OwnerControl::AdmitDurablePaymentV1 {
                record: Box::new(DurablePaymentAdmissionRecordV1 {
                    witness_native_review_digest: "13".repeat(32),
                    terms: DurablePaymentAdmissionTermsV1 {
                        version: 1,
                        identity: wholepact_core::manual_enrollment::ManualAccountIdentity {
                            account_id: "11".repeat(32),
                            full_viewing_key_digest: "14".repeat(32),
                            network_profile_id: "inert-network".into(),
                            derivation_domain: "inert-domain".into(),
                        },
                        original_policy_digest: "15".repeat(32),
                        original_genesis_digest: "16".repeat(32),
                        original_birth_commit_digest: "17".repeat(32),
                        original_roster_extension_digest: "18".repeat(32),
                        original_enrollment_ref: "19".repeat(32),
                        writer_certificate_digest: "1a".repeat(32),
                        fixed: DurableFixedCandidateBindingV1 {
                            schema_version: 1,
                            network_profile_id: "inert-network".into(),
                            agreement_id: "inert-agreement".into(),
                            obligation_id: "inert-obligation".into(),
                            proposal_id: "inert-proposal".into(),
                            revision: 1,
                            expiry_height: 2,
                            proposal_digest: "1b".repeat(32),
                            manifest_digest: "1c".repeat(32),
                            unsigned_artifact_digest: "1d".repeat(32),
                            proved_artifact_digest: "1e".repeat(32),
                            effects_commitment: "1f".repeat(32),
                            policy_digest: "20".repeat(32),
                            review_binding: "21".repeat(32),
                            action_mapping_digest: "22".repeat(32),
                            anchor: "23".repeat(32),
                            proposal_binding: "24".repeat(32),
                        },
                        authorization_id: "inert-authorization".into(),
                        recipient_policy_scope_digest: "25".repeat(32),
                        concrete_recipient_scope_digest: "26".repeat(32),
                        inputs: vec![wholepact_authority::InputReservation {
                            input_id: "inert-input".into(),
                            nullifier: "27".repeat(32),
                            action_index: 0,
                            value_zatoshis: 50,
                        }],
                        maximum_debit_zatoshis: 40,
                        fee_share_zatoshis: 2,
                        transaction_fee_zatoshis: 4,
                        valid_from_ms: 1,
                        valid_until_ms: 2,
                    },
                }),
            },
        }
    }

    #[test]
    fn historical_admission_observation_requires_exact_original_request() {
        let expected = historical_admission_data();
        assert!(require_historical_admission_observation_v1(
            &expected,
            Some(&expected),
            false,
            false,
            false,
            false,
        )
        .is_ok());
        for field in 0..10 {
            let mut changed = expected.clone();
            match field {
                0 => changed.operation_id.push_str("-replacement"),
                1 => changed.account_id = "30".repeat(32),
                2 => changed.network_profile_id.push_str("-other"),
                3 => changed.writer_epoch += 1,
                4 => changed.expected_head.sequence += 1,
                5 => changed.expected_head.digest = "31".repeat(32),
                6 => changed.control = wholepact_authority::OwnerControl::Pause,
                _ => {
                    let wholepact_authority::OwnerControl::AdmitDurablePaymentV1 { record } =
                        &mut changed.control
                    else {
                        panic!("expected inert admission data");
                    };
                    match field {
                        7 => record.terms.valid_until_ms += 1,
                        8 => record.terms.fixed.proved_artifact_digest = "32".repeat(32),
                        _ => record.terms.original_enrollment_ref = "33".repeat(32),
                    }
                }
            }
            assert!(matches!(
                require_historical_admission_observation_v1(
                    &expected,
                    Some(&changed),
                    false,
                    false,
                    false,
                    false,
                ),
                Err(Error::ReviewMismatch)
            ));
        }
    }

    #[test]
    fn historical_admission_observation_rejects_missing_or_non_admission_data() {
        let expected = historical_admission_data();
        // A supplied expectation/local retained intent without a successful
        // historical observation cannot advance the fixture to Admitted.
        assert!(matches!(
            require_historical_admission_observation_v1(
                &expected, None, false, false, false, false,
            ),
            Err(Error::ReviewMismatch)
        ));
        let mut not_admission = expected;
        not_admission.control = wholepact_authority::OwnerControl::Pause;
        assert!(matches!(
            require_historical_admission_observation_v1(
                &not_admission,
                Some(&not_admission),
                false,
                false,
                false,
                false,
            ),
            Err(Error::ReviewMismatch)
        ));
    }

    #[test]
    fn historical_admission_observation_rejects_pending_review_job_or_writer() {
        let expected = historical_admission_data();
        for [pending, job, receipt, reconciled] in [
            [true, false, false, false],
            [false, true, false, false],
            [false, false, true, false],
            [false, false, false, true],
            [true, true, true, true],
        ] {
            assert!(matches!(
                require_historical_admission_observation_v1(
                    &expected,
                    Some(&expected),
                    pending,
                    job,
                    receipt,
                    reconciled,
                ),
                Err(Error::ReviewMismatch)
            ));
        }
    }

    #[test]
    fn durable_inventory_comparison_does_not_hide_endpoint_directories_or_symlinks() {
        let root = tempfile::tempdir().unwrap();
        std::fs::write(root.path().join("original"), b"synthetic public marker").unwrap();
        let original = original_inventory(root.path()).unwrap();
        std::fs::create_dir(root.path().join("local-apps")).unwrap();
        assert!(matches!(
            original_inventory(root.path()),
            Err(Error::InvalidData)
        ));
        std::fs::remove_dir(root.path().join("local-apps")).unwrap();
        std::os::unix::fs::symlink("original", root.path().join("linked")).unwrap();
        assert!(matches!(
            original_inventory(root.path()),
            Err(Error::InvalidData)
        ));
        std::fs::remove_file(root.path().join("linked")).unwrap();
        assert_eq!(original_inventory(root.path()).unwrap(), original);
        std::fs::write(root.path().join("unexpected"), b"synthetic public marker").unwrap();
        assert_ne!(original_inventory(root.path()).unwrap(), original);
    }
    #[test]
    fn durable_focused_entry_rejects_unfocused_and_zero_epoch_before_effects() {
        let mut runtime = NativeRuntime::new(None);
        assert!(runtime.begin_durable_entry_v1(false, EPOCH).is_err());
        assert!(runtime.begin_durable_entry_v1(true, 0).is_err());
        assert!(runtime.durable_entry_job.is_none());
        assert!(runtime.open.is_none());
        assert!(runtime.pending.is_none());
        assert!(runtime.closing_accounts.is_empty());
    }
}

#[cfg(test)]
mod durable_flow_fixture_tests {
    use super::*;
    use flow_diag_v1::{
        DurableFlowCollectorV1 as Collector, DurableFlowErrorCodeV1 as Code,
        DurableFlowJobPurposeV1 as Purpose, DurableFlowReceiveV1 as Receive,
    };
    #[test]
    fn actual_fixture_missing_completion_records_terminal_without_inventing_first() {
        let collector = Collector::default();
        let observer = collector.arm(DurableFlowOperationV1::InitialSign);
        let result: Result<()> = DurableNativeFixtureV1::missing_flow_result_v1(
            Some(&observer),
            Err(Error::RecoveryRequired),
        );
        DurableNativeFixtureV1::observe_fixture_result_v1(
            Some(&observer),
            DurableFlowStageV1::Completion,
            &result,
        );
        assert!(matches!(result, Err(Error::RecoveryRequired)));
        let report = observer.finish(DurableFlowResultV1::ReturnedErr).unwrap();
        assert!(report.first_error().is_none());
        assert!(report.terminal_error().unwrap().code() == Code::SignerRecoveryRequired);
        assert!(report.terminal_error().unwrap().stage() == DurableFlowStageV1::Completion);
        assert!(report.completion().receive() == Receive::Missing);
        assert!(report.completion().result() == DurableFlowResultV1::NotObserved);
        assert!(report.completion().purpose().is_none());
    }
    #[test]
    fn actual_fixture_fallback_retains_real_source_failure_and_observed_result() {
        let collector = Collector::default();
        let observer = collector.arm(DurableFlowOperationV1::InitialSign);
        let job = observer.job_start(Purpose::WalletReview, 7);
        let original: Result<()> = flow_diag_v1::observe_result(
            Some(&observer),
            DurableFlowStageV1::WalletSource,
            Err(Error::Authentication),
        );
        job.received(DurableFlowStageV1::WalletSync, &original);
        let fallback: Result<()> = DurableNativeFixtureV1::missing_flow_result_v1(
            Some(&observer),
            Err(Error::ReviewMismatch),
        );
        DurableNativeFixtureV1::observe_fixture_result_v1(
            Some(&observer),
            DurableFlowStageV1::Completion,
            &fallback,
        );
        let report = observer.finish(DurableFlowResultV1::ReturnedErr).unwrap();
        assert!(report.first_error().unwrap().code() == Code::SignerAuthentication);
        assert!(report.first_error().unwrap().stage() == DurableFlowStageV1::WalletSource);
        assert!(report.terminal_error().unwrap().code() == Code::SignerReviewMismatch);
        assert!(report.terminal_error().unwrap().stage() == DurableFlowStageV1::Completion);
        assert!(report.completion().result() == DurableFlowResultV1::ReturnedErr);
        assert!(report.completion().receive() == Receive::Missing);
        assert!(report.completion().purpose() == Some(Purpose::WalletReview));
    }
}

#[cfg(test)]
mod acquire_reply_loss_fixture_tests {
    use super::*;
    use flow_diag_v1::{
        DurableFlowJobPurposeV1 as J, DurableFlowReceiveV1 as R,
        DurableFlowTransportPurposeV1 as P, DurableFlowTransportStageV1 as S,
    };
    use wholepact_authority::transport::history_diagnostics_v1::CheckedHistoryIoKindV1 as I;

    fn inert_facts() -> AcquireLossFactsV1 {
        AcquireLossFactsV1 {
            uncertain: true,
            complete: true,
            purpose: Some(J::Acquire),
            result: DurableFlowResultV1::ReturnedErr,
            receive: R::Received,
            suppressed: false,
            acquire_failed: true,
            other_calls: false,
            lower: Some((P::Acquire, S::ResponseRead, Some(I::Closed))),
            callback_failed: false,
            lower_authority_uncertain: true,
        }
    }
    #[test]
    fn expected_loss_classifier_requires_exact_actual_completion_and_lower_facts() {
        assert!(acquire_loss_facts_v1(inert_facts()));
        for mode in 0..17 {
            let mut facts = inert_facts();
            match mode {
                0 => facts.uncertain = false,
                1 => facts.complete = false,
                2 => facts.purpose = None,
                3 => facts.purpose = Some(J::AcquirePrepare),
                4 => facts.result = DurableFlowResultV1::ReturnedOk,
                5 => facts.result = DurableFlowResultV1::NotObserved,
                6 => facts.receive = R::Missing,
                7 => facts.receive = R::Disconnected,
                8 => facts.receive = R::Invalidated,
                9 => facts.suppressed = true,
                10 => facts.acquire_failed = false,
                11 => facts.other_calls = true,
                12 => facts.lower = None,
                13 => facts.lower = Some((P::Activate, S::ResponseRead, Some(I::Closed))),
                14 => facts.lower = Some((P::Acquire, S::RequestWrite, Some(I::Closed))),
                15 => facts.callback_failed = true,
                _ => facts.lower_authority_uncertain = false,
            }
            assert!(!acquire_loss_facts_v1(facts));
        }
        for io in [None, Some(I::Timeout), Some(I::Refused), Some(I::Other)] {
            let mut facts = inert_facts();
            facts.lower = Some((P::Acquire, S::ResponseRead, io));
            assert!(!acquire_loss_facts_v1(facts));
        }
    }
    #[test]
    fn pending_retry_phase_and_receipt_job_state_guards_are_closed() {
        for phase in [
            Phase::Pair,
            Phase::Paired,
            Phase::Accepted,
            Phase::Disclosure,
            Phase::Disclosed,
            Phase::Imported,
            Phase::AdmissionPrepared,
            Phase::Admitted,
            Phase::AcquireReplyLost,
            Phase::AcquireRetriedPending,
            Phase::FinancialImported,
            Phase::Signed,
        ] {
            assert_eq!(
                acquire_retry_phase_v1(phase, false),
                phase == Phase::AcquireReplyLost
            );
            assert!(!acquire_retry_phase_v1(phase, true));
        }
        assert!(acquire_idle_v1([false; 12]));
        for index in 0..12 {
            let mut flags = [false; 12];
            flags[index] = true;
            assert!(!acquire_idle_v1(flags));
        }
    }
    #[test]
    fn exact_immutable_acquire_correlations_reject_every_changed_dimension() {
        let deadline = Instant::now();
        let records = DurableNativeRecordsV1 {
            enrollment_ref: "inert-enrollment".into(),
            accepted_manifest_ref: "inert-manifest".into(),
        };
        let writer = Arc::new(());
        let owner = Arc::new(());
        let ledger = vec![(0, [0; 32]); 14];
        let before = AcquireReplyLossCorrelationV1 {
            entry: "inert-entry".into(),
            records: records.clone(),
            source_markers: [1, 2, 3],
            writer: writer.clone(),
            owner: owner.clone(),
            deadline,
            ledger: ledger.clone(),
            digest: "inert-review".into(),
            review_deadline: deadline,
            history_digest: "inert-history".into(),
            first_attempt: 1,
            retry_started: false,
        };
        assert!(acquire_immutable_equal_v1(
            &before,
            "inert-entry",
            &records,
            [1, 2, 3],
            &writer,
            &owner,
            deadline,
            &ledger
        ));
        for mode in 0..10 {
            let mut entry = "inert-entry";
            let mut changed_records = records.clone();
            let mut markers = [1, 2, 3];
            let mut changed_writer = writer.clone();
            let mut changed_owner = owner.clone();
            let mut changed_deadline = deadline;
            let mut changed_ledger = ledger.clone();
            match mode {
                0 => entry = "other-entry",
                1 => changed_records.enrollment_ref.push('x'),
                2 => changed_records.accepted_manifest_ref.push('x'),
                3 => markers[0] += 1,
                4 => markers[1] += 1,
                5 => markers[2] += 1,
                6 => changed_writer = Arc::new(()),
                7 => changed_owner = Arc::new(()),
                8 => changed_deadline += Duration::from_nanos(1),
                _ => changed_ledger[13].1[31] = 1,
            }
            assert!(!acquire_immutable_equal_v1(
                &before,
                entry,
                &changed_records,
                markers,
                &changed_writer,
                &changed_owner,
                changed_deadline,
                &changed_ledger
            ));
        }
        let mut changed = ledger.clone();
        changed[0].0 += 1;
        assert!(!acquire_immutable_equal_v1(
            &before,
            "inert-entry",
            &records,
            [1, 2, 3],
            &writer,
            &owner,
            deadline,
            &changed
        ));
        assert!(!acquire_immutable_equal_v1(
            &before,
            "inert-entry",
            &records,
            [1, 2, 3],
            &writer,
            &owner,
            deadline,
            &ledger[..13]
        ));
    }
}
