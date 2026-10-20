//! Separate actual financial lifecycle qualification. This does not change the
//! B1 admission-only baseline or revive a serialized source/consent capability.
use super::*;

use crate::host::financial_diagnostics_v1 as financial_diagnostic;
static FINANCIAL_FAILURE_EMITTED: AtomicBool = AtomicBool::new(false);
fn promote_financial_failure<T>(result: &Result<T>) {
    let captured = financial_diagnostic::take_operation_failure();
    if let Err(error) = result {
        if !FINANCIAL_FAILURE_EMITTED.swap(true, Ordering::SeqCst) {
            let captured = captured.or_else(|| {
                financial_diagnostic::host(
                    financial_diagnostic::FinancialStageV1::LifecycleHarness,
                    financial_diagnostic::FinancialCommitStateV1::NotEstablished,
                    error,
                );
                financial_diagnostic::take_operation_failure()
            });
            if let Some(captured) = captured {
                financial_diagnostic::emit(captured);
            }
        }
    }
}
fn financial_host_operation<T>(boundary: B, operation: impl FnOnce() -> Result<T>) -> Result<T> {
    financial_diagnostic::reset_operation();
    let result = diagnostic::host(boundary, operation);
    promote_financial_failure(&result);
    result
}

fn financial_witness_error(stage: financial_diagnostic::FinancialStageV1, boundary: B, error: wholepact_authority::AuthorityError) -> Error {
    financial_diagnostic::authority(stage, financial_diagnostic::FinancialCommitStateV1::OutcomeUncertain, &error);
    witness_error(boundary, error)
}

fn worker_error(label: &'static str) -> Error {
    use financial_diagnostic::{FinancialStageV1 as S, FinancialCommitStateV1 as C};
    let (stage, error) = match label {
        "durable worker cancelled" | "durable worker closed" | "durable command disconnected" => (S::WorkerCommand, Error::Locked),
        "durable reply disconnected" => (S::WorkerReply, Error::Locked),
        "durable worker panicked" => (S::WorkerDrain, Error::Authentication),
        "financial result original deadline expired" => (S::WorkerReturn, Error::Permission),
        "financial return stopped without exact completion" => (S::WorkerReturn, Error::HistoricalExportIncomplete),
        "financial return unexpected native purpose" => (S::WorkerReturn, Error::Authentication),
        // Known typed job failures were captured before the worker returned this
        // inert label. This fallback cannot overwrite their precise first cause.
        _ => (S::WorkerReply, Error::Receipt("exact original delivery worker refused".into())),
    };
    financial_diagnostic::host(stage, C::OutcomeUncertain, &error);
    super::worker_error(label)
}

fn done(worker: &worker::JoinedSignerWorkerV1, index: usize) -> Result<()> {
    match worker.receive().map_err(worker_error)? {
        R::Done { index: actual } if actual == index => Ok(()),
        _ => {
            let error = Error::Authentication;
            financial_diagnostic::host(financial_diagnostic::FinancialStageV1::WorkerReply,
                financial_diagnostic::FinancialCommitStateV1::OutcomeUncertain, &error);
            Err(error)
        }
    }
}

const FINANCIAL_PUBLIC_PREFIX: &str = "CI_SYNTHETIC_DURABLE_FINANCIAL ";
const FINANCIAL_DEATH_MARKER: &str = "SYNTHETIC_DURABLE_FINANCIAL_COMPLETED_V1=1";

#[derive(Clone, Copy, Serialize, Deserialize)]
enum FinancialBoundaryV1 {
    OriginalPreparation,
    ContinuationAdmission,
    SignatureAndIntake,
    FinalTransactionRetention,
    ProducerDeath,
    CompletedReopen,
    DispatchAdmission,
    PartialAdmissionReconciliation,
    SavedTransactionDispatch,
    ReaderReap,
    RootCleanup,
}
// Finite diagnostic vocabulary only. This records the active boundary, not a
// causal error or successful effect. The parent reads it only after verified reap.
const FINANCIAL_STAGES: &[u8] = b"durable-financial-stages-v1.jsonl\0";
const MAX_STAGE_BYTES: u64 = 4096;
fn financial_stage(root: &Path, stage: FinancialBoundaryV1) -> io::Result<()> {
    let directory = directory(root)?;
    let mut output = file(
        &directory,
        FINANCIAL_STAGES,
        libc::O_WRONLY | libc::O_CREAT | libc::O_APPEND,
    )?;
    check_file(&output)?;
    let mut bytes = serde_json::to_vec(&stage).map_err(|_| invalid())?;
    bytes.push(b'\n');
    if output
        .metadata()?
        .len()
        .checked_add(bytes.len() as u64)
        .ok_or_else(invalid)?
        > MAX_STAGE_BYTES
    {
        return Err(invalid());
    }
    output.write_all(&bytes)?;
    output.sync_all()?;
    directory.sync_all()
}
fn last_financial_stage(root: &Path) -> io::Result<FinancialBoundaryV1> {
    let directory = directory(root)?;
    let input = file(&directory, FINANCIAL_STAGES, libc::O_RDONLY)?;
    check_file(&input)?;
    let mut bytes = Vec::new();
    input.take(MAX_STAGE_BYTES + 1).read_to_end(&mut bytes)?;
    if bytes.len() as u64 > MAX_STAGE_BYTES || bytes.last() != Some(&b'\n') {
        return Err(invalid());
    }
    let mut last = None;
    for line in bytes[..bytes.len() - 1].split(|byte| *byte == b'\n') {
        last = Some(serde_json::from_slice(line).map_err(|_| invalid())?);
    }
    last.ok_or_else(invalid)
}
pub(in crate::host::manual_enrollment::command::roster_publication_v2::sequential_construction_v3::qualification) fn record_financial_preparation_v1(
) -> Result<()> {
    financial_stage(&scenario_root()?, FinancialBoundaryV1::OriginalPreparation)?;
    Ok(())
}
// Failure-only observations from the actual retained-wallet adapters and the
// original isolated provider. Counters are not a causal or atomic timeline.
const TRANSPORT_FAILURE_FILE: &[u8] = b"durable-financial-transport-failure-v1.json\0";
const MAX_TRANSPORT_FAILURE_BYTES: u64 = 2048;
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct FinancialTransportFailureV1 {
    chain: wholepact_chain::TransportDiagnosticSnapshot,
    provider: synthetic_born_provider_v1::SyntheticProviderDiagnosticsV1,
}
impl FinancialTransportFailureV1 {
    fn validate(&self) -> bool {
        self.chain.validate() && self.provider.validate()
    }
}
pub(in crate::host::manual_enrollment::command::roster_publication_v2::sequential_construction_v3::qualification) fn record_financial_transport_failure_v1(
    chain: wholepact_chain::TransportDiagnosticSnapshot,
    provider: synthetic_born_provider_v1::SyntheticProviderDiagnosticsV1,
) -> io::Result<()> {
    let value = FinancialTransportFailureV1 { chain, provider };
    if !value.validate()
        || serde_json::to_vec(&value).map_err(|_| invalid())?.len() as u64
            > MAX_TRANSPORT_FAILURE_BYTES
    {
        return Err(invalid());
    }
    write_record(
        &scenario_root().map_err(|_| invalid())?,
        TRANSPORT_FAILURE_FILE,
        &value,
    )
}
fn read_financial_transport_failure(
    root: &Path,
) -> io::Result<Option<FinancialTransportFailureV1>> {
    let directory = directory(root)?;
    let input = match file(&directory, TRANSPORT_FAILURE_FILE, libc::O_RDONLY) {
        Ok(input) => input,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error),
    };
    check_file(&input)?;
    let mut bytes = Vec::new();
    input
        .take(MAX_TRANSPORT_FAILURE_BYTES + 1)
        .read_to_end(&mut bytes)?;
    if bytes.len() as u64 > MAX_TRANSPORT_FAILURE_BYTES {
        return Err(invalid());
    }
    let value: FinancialTransportFailureV1 =
        serde_json::from_slice(&bytes).map_err(|_| invalid())?;
    if !value.validate() {
        return Err(invalid());
    }
    Ok(Some(value))
}
#[derive(Clone, Copy, Serialize)]
#[serde(rename_all = "snake_case")]
enum FinancialOutcomeV1 {
    Complete,
    Refused,
    Uncertain,
    Expired,
    Conflict,
    Unverified,
}

/// A bounded public projection, never transaction data, a receipt or authority.
/// Proof fields start false and may only be assigned from actual verified results.
#[derive(Serialize)]
struct FinancialPublicV1 {
    schema: u16,
    result: &'static str,
    first_failure: Option<FinancialBoundaryV1>,
    boundary_outcome: Option<FinancialOutcomeV1>,
    source_failure_boundary: Option<&'static str>,
    source_failure_outcome: Option<&'static str>,
    failed_child_inputs_completed: Option<usize>,
    failed_child_inputs_expected: Option<usize>,
    private_fixed_primary:
        Option<crate::host::financial::private_durable_fixed_v2::PrivateDiagnosticPrimaryV1>,
    source_diagnostic_withheld: bool,
    financial_diagnostic: Option<crate::host::financial_diagnostics_v1::FinancialDiagnosticV1>,
    transport_failure: Option<FinancialTransportFailureV1>,
    producer_reaped: bool,
    producer_group_absent: bool,
    reader_reaped: bool,
    reader_group_absent: bool,
    root_cleanup: &'static str,
    source_prefix_preserved: bool,
    both_continuations_authenticated: bool,
    both_results_before_process_death: bool,
    exact_completed_reopen_after_death: bool,
    completed_extraction_checkpoint_count: u8,
    dedicated_dispatch_admissions: u8,
    identical_saved_bytes_dispatched: bool,
    partial_admission_reconciled: bool,
    bounded_admission_retry_same_bytes: bool,
    original_expiry_preserved: bool,
    stale_head_refused: bool,
    synthetic_backend_only: bool,
    public_chain_verified: bool,
}
impl FinancialPublicV1 {
    fn pending() -> Self {
        Self {
            schema: 4,
            result: "failed",
            first_failure: None,
            boundary_outcome: None,
            source_failure_boundary: None,
            source_failure_outcome: None,
            failed_child_inputs_completed: None,
            failed_child_inputs_expected: None,
            private_fixed_primary: None,
            source_diagnostic_withheld: false,
            financial_diagnostic: None,
            transport_failure: None,
            producer_reaped: false,
            producer_group_absent: false,
            reader_reaped: false,
            reader_group_absent: false,
            root_cleanup: "unverified",
            source_prefix_preserved: false,
            both_continuations_authenticated: false,
            both_results_before_process_death: false,
            exact_completed_reopen_after_death: false,
            completed_extraction_checkpoint_count: 0,
            dedicated_dispatch_admissions: 0,
            identical_saved_bytes_dispatched: false,
            partial_admission_reconciled: false,
            bounded_admission_retry_same_bytes: false,
            original_expiry_preserved: false,
            stale_head_refused: false,
            synthetic_backend_only: true,
            public_chain_verified: false,
        }
    }
    fn fail(&mut self, boundary: FinancialBoundaryV1, outcome: FinancialOutcomeV1) {
        if self.first_failure.is_none() {
            self.first_failure = Some(boundary);
            self.boundary_outcome = Some(outcome);
        }
        self.result = "failed";
    }
    fn observe_failed_child(&mut self, child: &PrivateWorkspaceStageResultV1) {
        // This remains pending private evidence until emit_once applies cleanup.
        if !child.process.verified() {
            self.source_diagnostic_withheld = true;
            return;
        }
        if child.expected == 0 || child.expected > 512 || child.next > child.expected {
            self.source_diagnostic_withheld = true;
            return;
        }
        self.financial_diagnostic = child.financial_diagnostic.clone();
        self.failed_child_inputs_completed = Some(child.next);
        self.failed_child_inputs_expected = Some(child.expected);
        if let Some(pair) = child.delivery_first_failure {
            let (boundary, outcome) = pair.labels();
            self.source_failure_boundary = Some(boundary);
            self.source_failure_outcome = Some(outcome);
        }
        self.private_fixed_primary = child
            .private_fixed_diagnostic()
            .map(|diagnostic| diagnostic.primary.clone());
        self.source_diagnostic_withheld |= child.diagnostic_withheld();
    }
    fn verified(&self) -> bool {
        self.first_failure.is_none()
            && self.boundary_outcome.is_none()
            && self.source_failure_boundary.is_none()
            && self.source_failure_outcome.is_none()
            && self.failed_child_inputs_completed.is_none()
            && self.failed_child_inputs_expected.is_none()
            && self.private_fixed_primary.is_none()
            && self.transport_failure.is_none()
            && self.financial_diagnostic.is_none()
            && !self.source_diagnostic_withheld
            && self.producer_reaped
            && self.producer_group_absent
            && self.reader_reaped
            && self.reader_group_absent
            && self.root_cleanup == "closed_absent"
            && self.source_prefix_preserved
            && self.both_continuations_authenticated
            && self.both_results_before_process_death
            && self.exact_completed_reopen_after_death
            && self.completed_extraction_checkpoint_count == 1
            && self.dedicated_dispatch_admissions == 2
            && self.identical_saved_bytes_dispatched
            && self.partial_admission_reconciled
            && self.bounded_admission_retry_same_bytes
            && self.original_expiry_preserved
            && self.stale_head_refused
            && self.synthetic_backend_only
            && !self.public_chain_verified
    }
    fn withhold_unverified_diagnostics(&mut self) {
        let reader_failure = matches!(
            self.first_failure,
            Some(
                FinancialBoundaryV1::CompletedReopen
                    | FinancialBoundaryV1::DispatchAdmission
                    | FinancialBoundaryV1::PartialAdmissionReconciliation
                    | FinancialBoundaryV1::SavedTransactionDispatch
                    | FinancialBoundaryV1::ReaderReap
            )
        );
        if self.root_cleanup != "closed_absent"
            || !self.producer_reaped
            || !self.producer_group_absent
            || (reader_failure && (!self.reader_reaped || !self.reader_group_absent))
        {
            self.source_failure_boundary = None;
            self.source_failure_outcome = None;
            self.failed_child_inputs_completed = None;
            self.failed_child_inputs_expected = None;
            self.private_fixed_primary = None;
            self.source_diagnostic_withheld = true;
            self.transport_failure = None;
            self.financial_diagnostic = None;
        }
    }
    fn emit_once(mut self) -> io::Result<()> {
        self.withhold_unverified_diagnostics();
        if self.verified() {
            self.result = "passed";
        } else if self.first_failure.is_none() {
            self.fail(
                FinancialBoundaryV1::SavedTransactionDispatch,
                FinancialOutcomeV1::Unverified,
            );
        }
        let bytes = serde_json::to_string(&self).map_err(|_| invalid())?;
        if bytes.len() > 4096
            || self.completed_extraction_checkpoint_count > 1
            || self.dedicated_dispatch_admissions > 2
        {
            return Err(invalid());
        }
        eprintln!("{FINANCIAL_PUBLIC_PREFIX}{bytes}");
        if self.result == "passed" {
            Ok(())
        } else {
            Err(invalid())
        }
    }
}

use wholepact_authority::{OwnerControl, OwnerControlRequest};
use wholepact_signer::native_ui::synthetic_born_joined_qualification::FinancialQualificationPhaseV1 as Phase;
const FINANCIAL_READY: &[u8] = b"durable-financial-original-v1.json\0";
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct FinancialReadyV1 {
    schema: u16,
    profile: PathBuf,
    workspace: PathBuf,
    financial: PathBuf,
    fixed_prefix_digest: String,
    export_history_digest: String,
    continuations: [OwnerControlRequest; 2],
    witness_reopen: Vec<u8>,
    provider_reopen: Vec<u8>,
    provider_reopen_digest: String,
    fixed_identity: serde_json::Value,
    original_valid_until_ms: u64,
    transaction_checkpoint_id: String,
    transaction_digest: String,
    transaction_id: String,
    signed_result_id: String,
}
fn financial_phase(worker: &worker::JoinedSignerWorkerV1, index: usize) -> Result<Phase> {
    worker
        .send(C::PollFinancialContinuation(index))
        .map_err(worker_error)?;
    match worker.receive().map_err(worker_error)? {
        R::FinancialPhase {
            index: actual,
            phase,
        } if actual == index => Ok(phase),
        _ => Err(Error::Authentication),
    }
}
fn financial_wait(
    worker: &worker::JoinedSignerWorkerV1,
    index: usize,
    target: Phase,
) -> Result<()> {
    let result = (|| {
    let deadline = private_fixed_v2::child_original_cutoff()?;
    loop {
        if Instant::now() >= deadline {
            return Err(Error::Permission);
        }
        let phase = financial_phase(worker, index)?;
        if phase == target {
            return Ok(());
        }
        if !matches!(phase, Phase::Working | Phase::Opening) {
            return Err(Error::Authentication);
        }
        std::thread::sleep(Duration::from_millis(5));
    }
    })();
    if let Err(error) = &result {
        financial_diagnostic::host(financial_diagnostic::FinancialStageV1::WorkerPhaseWait,
            financial_diagnostic::FinancialCommitStateV1::OutcomeUncertain, error);
    }
    result
}

fn financial_approve(worker: &worker::JoinedSignerWorkerV1, index: usize) -> Result<()> {
    worker
        .send(C::ApproveFinancialContinuation(index))
        .map_err(worker_error)?;
    done(worker, index)
}

#[allow(clippy::too_many_arguments)]
pub(super) fn continue_financial_producer(
    terminal: crate::terminal::Terminal,
    host: Host,
    mut original: initial::PrivateWorkspaceInitialV1,
    profile: PathBuf,
    workspace: PathBuf,
    financial: PathBuf,
    fixed_prefix_digest: String,
    export_history_digest: String,
    admissions: [DurableDeliveryAdmissionStatusV3; 2],
    _recipient_intents: [RecipientIntentV3; 2],
    runtime: tokio::runtime::Runtime,
    provider: synthetic_born_provider_v1::SyntheticBornProviderV1,
    wallet_setup: String,
) -> Result<()> {
    financial_diagnostic::reset_operation();
    let result = (|| -> Result<()> {
        let scenario = scenario_root()?;
        financial_stage(&scenario, FinancialBoundaryV1::ContinuationAdmission)?;
        let mut continuations = Vec::new();
        for index in 1..=2 {
            financial_stage(&scenario, FinancialBoundaryV1::ContinuationAdmission)?;
            let original_admission = &admissions[index - 1];
            let server = original
                .witness
                .serve_committed_durable_delivery_history_v2(&original_admission.request.operation_id)
                .map_err(|e| financial_witness_error(financial_diagnostic::FinancialStageV1::WitnessHistoryService, B::DeliveryHistoricalRead, e))?;
            original
                .signers
                .send(C::BeginFinancialContinuation(index, wallet_setup.clone()))
                .map_err(worker_error)?;
            done(&original.signers, index)?;
            financial_wait(&original.signers, index, Phase::ReadReview)?;
            financial_approve(&original.signers, index)?;
            financial_wait(&original.signers, index, Phase::ContinueReview)?;
            financial_approve(&original.signers, index)?;
            financial_wait(&original.signers, index, Phase::AwaitingAdmission)?;
            original
                .signers
                .send(C::ReadFinancialContinuationRequest(index))
                .map_err(worker_error)?;
            let request = match original.signers.receive().map_err(worker_error)? {
                R::FinancialRequest {
                    index: actual,
                    request: Some(request),
                } if actual == index => request,
                _ => return Err(Error::Authentication),
            };
            let OwnerControl::AdmitFinancialContinuationV1 { record } = &request.control else {
                return Err(Error::Authentication);
            };
            if record.terms.original_delivery_operation_id!=original_admission.request.operation_id
                || record.terms.original_delivery_request_digest!=wholepact_authority::durable_financial_continuation_v1::original_delivery_request_digest_v1(&original_admission.request).map_err(|_|Error::Authentication)? {
                return Err(Error::Authentication);
            }
            drop(server);
            original
                .witness
                .start_exact_financial_continuation_v1(&request.account_id, &request)
                .map_err(|e| financial_witness_error(financial_diagnostic::FinancialStageV1::WitnessContinuationReview, B::DeliveryNativeAdmission, e))?;
            original
                .signers
                .send(C::SendFinancialContinuation(index))
                .map_err(worker_error)?;
            done(&original.signers, index)?;
            financial_wait(&original.signers, index, Phase::AdmitReview)?;
            financial_approve(&original.signers, index)?;
            original
                .witness
                .finish_exact_financial_continuation_v1()
                .map_err(|e| financial_witness_error(financial_diagnostic::FinancialStageV1::WitnessContinuationCommit, B::DeliveryNativeAdmission, e))?;
            let server = original
                .witness
                .serve_committed_financial_signing_v1(&request.operation_id)
                .map_err(|e| financial_witness_error(financial_diagnostic::FinancialStageV1::WitnessSigningService, B::DeliveryNativeAdmission, e))?;
            financial_stage(&scenario, FinancialBoundaryV1::SignatureAndIntake)?;
            // Each action below is a real fresh final-primary review. No synthetic
            // decision, signature, session or historical grant is manufactured.
            for phase in [
                Phase::ReadReview,
                Phase::AcquireReview,
                Phase::ReadReview,
                Phase::ActivateReview,
                Phase::WalletReview,
                Phase::ReadReview,
                Phase::SignReview,
            ] {
                financial_wait(&original.signers, index, phase)?;
                financial_approve(&original.signers, index)?;
            }
            financial_wait(&original.signers, index, Phase::AwaitingReturn)?;
            drop(server);
            continuations.push(request);
        }
        let continuations: [OwnerControlRequest; 2] = continuations
            .try_into()
            .map_err(|_| Error::Authentication)?;
        let server = original
            .witness
            .serve_committed_completed_dispatch_pair_v1()
            .map_err(|e| financial_witness_error(financial_diagnostic::FinancialStageV1::WitnessCompletedPairService, B::DeliveryHistoricalRead, e))?;
        let first = financial_host_operation(B::DeliveryHistoricalRead, || {
            host.read_original_financial_history_v1(
                &workspace,
                &continuations[0].account_id,
                &continuations[0].operation_id,
            )
        })?;
        let second = financial_host_operation(B::DeliveryHistoricalRead, || {
            host.read_original_financial_history_v1(
                &workspace,
                &continuations[1].account_id,
                &continuations[1].operation_id,
            )
        })?;
        if first.continuation_request() != &continuations[0]
            || second.continuation_request() != &continuations[1]
        {
            return Err(Error::Authentication);
        }
        financial_stage(&scenario, FinancialBoundaryV1::SignatureAndIntake)?;
        financial_host_operation(B::PrivateWorkspaceIntake, || {
            host.bind_original_financial_continuations_v1(
                &workspace,
                "synthetic-financial-bind-v1",
                [&first, &second],
            )
        })?;
        for index in 1..=2 {
            original
                .signers
                .send(C::ReadFinancialResultPeer(index))
                .map_err(worker_error)?;
            let (peer, request) = match original.signers.receive().map_err(worker_error)? {
                R::FinancialResultPeer {
                    index: actual,
                    peer,
                    request,
                } if actual == index => (peer, request),
                _ => return Err(Error::Authentication),
            };
            let stop = Arc::new(AtomicBool::new(false));
            original
                .signers
                .send(C::ServeFinancialResult(index, stop.clone()))
                .map_err(worker_error)?;
            let result = (|| {
                let receiver=wholepact_signer::authority_bridge::financial_continuation_v1::PreparedFinancialResultReceiverV1::prepare(peer.provider,&peer.endpoint,&request,peer.deadline).map_err(bridge_error)?;
                financial_host_operation(B::PrivateWorkspaceIntake, || {
                    host.intake_original_financial_result_v1(
                        &workspace,
                        &format!("synthetic-financial-intake-{index}"),
                        receiver,
                        if index == 1 { &first } else { &second },
                    )
                })
            })();
            stop.store(true, Ordering::Release);
            let returned = done(&original.signers, index);
            result?;
            returned?;
            original
                .signers
                .send(C::PreserveFinancialContinuation(index))
                .map_err(worker_error)?;
            match original.signers.receive().map_err(worker_error)? {
                R::DeliveryPreserved { index: actual, .. } if actual == index => (),
                _ => return Err(Error::Authentication),
            }
        }
        financial_stage(&scenario, FinancialBoundaryV1::FinalTransactionRetention)?;
        let completed = financial_host_operation(B::PrivateWorkspaceCheckpoint, || {
            host.complete_original_financial_transaction_v1(
                &workspace,
                "synthetic-financial-complete-v1",
            )
        })?;
        if completed.exact_replay
            || !completed.cryptographic_transaction_verified
            || !completed.transaction_extracted
            || completed.chain_validated
            || completed.authorization_allowed
            || completed.distribution_allowed
            || completed.release_allowed
        {
            return Err(Error::Authentication);
        }
        let OwnerControl::AdmitFinancialContinuationV1 { record } = &continuations[0].control else {
            return Err(Error::Authentication);
        };
        let summary = financial_host_operation(B::PrivateWorkspaceReadFixed, || {
            host.verify_completed_private_financial_summary_v1(
                &workspace,
                &record.terms.scope.delivery.submission_operation_id,
            )
        })?;
        if summary.checkpoint_id != completed.checkpoint_id
            || summary.transaction_digest != completed.transaction_digest
            || summary.transaction_id != completed.txid
            || summary.frozen_export_history_digest != export_history_digest
            || summary.fixed_identity != serde_json::to_value(&record.terms.scope.authorization.fixed)?
            || summary.next_delegation_attempt != 1
            || summary.latest_requests.is_some()
        {
            return Err(Error::Authentication);
        }
        let provider_reopen = provider.preserve_public_original_v1()?;
        drop(first);
        drop(second);
        drop(server);
        original.signers.shutdown().map_err(worker_error)?;
        runtime.block_on(provider.shutdown()).map_err(Error::from)?;
        drop(runtime);
        let witness_reopen = original
            .witness
            .preserve_financial_originals_v1()
            .map_err(|e| financial_witness_error(financial_diagnostic::FinancialStageV1::WitnessOriginalPreserve, B::DeliveryHistoricalRead, e))?;
        let ready = FinancialReadyV1 {
            schema: 1,
            profile,
            workspace,
            financial,
            fixed_prefix_digest,
            export_history_digest,
            continuations,
            witness_reopen,
            provider_reopen_digest: digest(&provider_reopen)?,
            provider_reopen,
            fixed_identity: summary.fixed_identity,
            original_valid_until_ms: summary.original_valid_until_ms,
            transaction_checkpoint_id: completed.checkpoint_id,
            transaction_digest: completed.transaction_digest,
            transaction_id: completed.txid,
            signed_result_id: completed.signed_result_id,
        };
        let approval=terminal.approve_historical("SYNTHETIC ORIGINAL FINANCIAL: both genuine signature results are already retained and one immutable final transaction is saved. Close all signer and provider workers, retain these exact original files, then permit controlled producer process death. A successor may only verify the completed original and request a fresh bounded dispatch; no signature or extraction may be recreated.")?;
        approval.effect(&mut || {
            ready.validate(&scenario)?;
            write_record(&scenario, FINANCIAL_READY, &ready)?;
            Ok(())
        })?;
        terminal.message(&format!("{FINANCIAL_DEATH_MARKER}\n"))?;
        let _keep_actual_originals = (&host, &original.temporary);
        loop {
            std::thread::park();
        }
    })();
    promote_financial_failure(&result);
    result
}

impl FinancialReadyV1 {
    fn validate(&self, root: &Path) -> io::Result<()> {
        if self.schema != 1
            || self.witness_reopen.is_empty()
            || self.witness_reopen.len() > MAX_CONTROL as usize
            || self.provider_reopen.is_empty()
            || self.provider_reopen.len() > MAX_CONTROL as usize
            || self.original_valid_until_ms == 0
            || digest(&self.provider_reopen).map_err(|_| invalid())? != self.provider_reopen_digest
            || !hash(&self.fixed_prefix_digest)
            || !hash(&self.export_history_digest)
            || !hash(&self.transaction_digest)
            || !hash(&self.transaction_id)
            || self.transaction_checkpoint_id.is_empty()
            || self.transaction_checkpoint_id.len() > 256
            || self.signed_result_id.is_empty()
            || self.signed_result_id.len() > 256
        {
            return Err(invalid());
        }
        for path in [&self.profile, &self.workspace, &self.financial] {
            let relative = path.strip_prefix(root).map_err(|_| invalid())?;
            if !path.is_absolute()
                || path.as_os_str().len() > 4096
                || relative.as_os_str().is_empty()
                || !relative
                    .components()
                    .all(|part| matches!(part, Component::Normal(_)))
            {
                return Err(invalid());
            }
        }
        if self.profile == self.workspace
            || self.profile == self.financial
            || self.workspace == self.financial
            || self.continuations[0].account_id == self.continuations[1].account_id
        {
            return Err(invalid());
        }
        let mut plan = None;
        for request in &self.continuations {
            let OwnerControl::AdmitFinancialContinuationV1 { record } = &request.control else {
                return Err(invalid());
            };
            record
                .validate_request(request, &record.terms.scope.witness)
                .map_err(|_| invalid())?;
            if plan
                .as_ref()
                .is_some_and(|p| p != &record.terms.scope.delivery)
            {
                return Err(invalid());
            }
            plan = Some(record.terms.scope.delivery.clone());
        }
        Ok(())
    }
    fn read_original(root: &Path) -> io::Result<Self> {
        let ready: Self = read_record(root, FINANCIAL_READY)?;
        ready.validate(root)?;
        Ok(ready)
    }
}
fn financial_owner_input(inputs: &mut Vec<Input<'static>>) {
    inputs.push(review(
        "Inspect this exact original financial continuation and saved proof",
    ));
}
fn financial_history_inputs(inputs: &mut Vec<Input<'static>>) {
    financial_owner_input(inputs);
    inputs.push(review("Read the complete authenticated original financial Witness history through the planned dispatcher"));
}
fn financial_producer_inputs() -> Vec<Input<'static>> {
    let mut inputs = producer_inputs();
    inputs.pop(); // B1 death prompt only.
    for _ in 0..2 {
        financial_history_inputs(&mut inputs);
    }
    financial_owner_input(&mut inputs);
    inputs.push(review("Read this exact original saved fixed proof and both original financial continuation records."));
    inputs.push(review(
        "Record the two authenticated owner financial continuations",
    ));
    for _ in 0..2 {
        financial_owner_input(&mut inputs);
        inputs.push(review(
            "Read the exact original financial fixed proof and existing intake lineage",
        ));
        inputs.push(review(
            "Verify and retain one actual authenticated original signer result",
        ));
        inputs.push(review(
            "Approve retain exact usable signatures for this EXACT scope?",
        ));
        inputs.push(review("Prepare this ONE EXACT local signature intake"));
    }
    financial_owner_input(&mut inputs);
    inputs.push(review(
        "Read and verify the exact two retained financial signer results and original proof.",
    ));
    inputs.push(review(
        "Combine only the two exact retained original signature subsets",
    ));
    financial_three_scope_retention_inputs(&mut inputs);
    inputs.push(review(
        "Approve extract/read and retain exact complete transaction for this EXACT scope?",
    ));
    financial_audit_inputs(&mut inputs);
    inputs.push(review(
        "SYNTHETIC ORIGINAL FINANCIAL: both genuine signature results are already retained",
    ));
    inputs
}

pub(in crate::host::manual_enrollment::command::roster_publication_v2::sequential_construction_v3::qualification) fn death_marker_financial_v1(
    tail: &str,
    producer: bool,
    complete: bool,
    terminal: bool,
) -> io::Result<bool> {
    if tail.lines().any(|line| {
        matches!(
            line,
            "SYNTHETIC_PRIVATE_FIXED_DURABLE_V1=1" | "SYNTHETIC_DURABLE_DELIVERY_ADMITTED_V2=1"
        )
    }) {
        return Err(invalid());
    }
    let count = tail
        .split_inclusive('\n')
        .filter(|line| {
            line.ends_with('\n') && line.trim_end_matches(['\r', '\n']) == FINANCIAL_DEATH_MARKER
        })
        .count();
    if count > 1 || (count == 1 && (!producer || !complete)) {
        return Err(invalid());
    }
    if terminal {
        let remainder = tail.rsplit_once('\n').map_or(tail, |(_, rest)| rest);
        if (!remainder.is_empty()
            && (FINANCIAL_DEATH_MARKER.starts_with(remainder)
                || remainder.starts_with(FINANCIAL_DEATH_MARKER)))
            || count != 1
        {
            return Err(invalid());
        }
    }
    Ok(count == 1)
}

// Exact production order: both source scopes sorted by retained result ID,
// then their retained union. Each actual prompt includes its full exact scope.
// This helper is never used by singleton result intake.
fn financial_three_scope_retention_inputs(inputs: &mut Vec<Input<'static>>) {
    for _ in 0..3 {
        inputs.push(review(
            "Approve retain exact usable signatures for this EXACT scope?",
        ));
    }
}

fn financial_audit_inputs(inputs: &mut Vec<Input<'static>>) {
    financial_owner_input(inputs);
    inputs.push(review("Read and verify the exact completed original financial transaction and retained dispatch lineage"));
    financial_three_scope_retention_inputs(inputs);
    inputs.push(review(
        "Approve extract/read and retain exact complete transaction for this EXACT scope?",
    ));
}

const FINANCIAL_FINISHED: &[u8] = b"durable-financial-completion-v1.json\0";
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct FinancialCompletionV1 {
    schema: u16,
    source_prefix_preserved: bool,
    both_continuations_authenticated: bool,
    both_results_before_process_death: bool,
    exact_completed_reopen_after_death: bool,
    completed_extraction_checkpoint_count: u8,
    dedicated_dispatch_admissions: u8,
    identical_saved_bytes_dispatched: bool,
    partial_admission_reconciled: bool,
    bounded_admission_retry_same_bytes: bool,
    original_expiry_preserved: bool,
    stale_head_refused: bool,
    synthetic_backend_only: bool,
    public_chain_verified: bool,
}
impl FinancialCompletionV1 {
    fn apply_checked(self, public: &mut FinancialPublicV1) -> io::Result<()> {
        if self.schema != 1
            || self.completed_extraction_checkpoint_count != 1
            || self.dedicated_dispatch_admissions != 2
            || !self.source_prefix_preserved
            || !self.both_continuations_authenticated
            || !self.both_results_before_process_death
            || !self.exact_completed_reopen_after_death
            || !self.identical_saved_bytes_dispatched
            || !self.partial_admission_reconciled
            || !self.bounded_admission_retry_same_bytes
            || !self.original_expiry_preserved
            || !self.stale_head_refused
            || !self.synthetic_backend_only
            || self.public_chain_verified
        {
            return Err(invalid());
        }
        public.source_prefix_preserved = self.source_prefix_preserved;
        public.both_continuations_authenticated = self.both_continuations_authenticated;
        public.both_results_before_process_death = self.both_results_before_process_death;
        public.exact_completed_reopen_after_death = self.exact_completed_reopen_after_death;
        public.completed_extraction_checkpoint_count = self.completed_extraction_checkpoint_count;
        public.dedicated_dispatch_admissions = self.dedicated_dispatch_admissions;
        public.identical_saved_bytes_dispatched = self.identical_saved_bytes_dispatched;
        public.partial_admission_reconciled = self.partial_admission_reconciled;
        public.bounded_admission_retry_same_bytes = self.bounded_admission_retry_same_bytes;
        public.original_expiry_preserved = self.original_expiry_preserved;
        public.stale_head_refused = self.stale_head_refused;
        public.synthetic_backend_only = self.synthetic_backend_only;
        public.public_chain_verified = self.public_chain_verified;
        Ok(())
    }
}
fn require_completed_original(
    ready: &FinancialReadyV1,
    summary: &crate::host::financial::private_financial_v1::CompletedPrivateFinancialSummaryV1,
) -> Result<()> {
    if summary.checkpoint_id != ready.transaction_checkpoint_id
        || summary.transaction_digest != ready.transaction_digest
        || summary.transaction_id != ready.transaction_id
        || summary.fixed_identity != ready.fixed_identity
        || summary.frozen_export_history_digest != ready.export_history_digest
        || summary.original_valid_until_ms != ready.original_valid_until_ms
    {
        return Err(Error::Authentication);
    }
    Ok(())
}
pub(in crate::host::manual_enrollment::command::roster_publication_v2::sequential_construction_v3::qualification) fn read_financial_child(
    terminal: crate::terminal::Terminal,
) -> Result<()> {
    financial_diagnostic::reset_operation();
    let result = diagnostic::host(B::PrivateWorkspaceReaderOpen, || {
        read_financial_child_inner(terminal)
    });
    promote_financial_failure(&result);
    result
}
fn read_financial_child_inner(terminal: crate::terminal::Terminal) -> Result<()> {
    let scenario = scenario_root()?;
    financial_stage(&scenario, FinancialBoundaryV1::CompletedReopen)?;
    let ready = FinancialReadyV1::read_original(&scenario)?;
    terminal.message(&format!(
        "SYNTHETIC_PRIVATE_NEW_SESSION_PATH={}\n",
        scenario.join("financial-reader-v4-session.token").display()
    ))?;
    let host = Host::open_workspace_dispatcher_registered_v4(
        terminal,
        &ready.profile,
        &ready.workspace,
        false,
    )?;
    if host
        .financial
        .as_ref()
        .ok_or(Error::Locked)?
        .current_directory()?
        != ready.financial
    {
        return Err(Error::Authentication);
    }
    let mut witness=wholepact_authority::native_witness_owner::EphemeralNativeWitnessV1::reopen_financial_originals_v1(&ready.witness_reopen)
        .map_err(|e|financial_witness_error(financial_diagnostic::FinancialStageV1::WitnessOriginalReopen, B::DeliveryOriginalReopen,e))?;
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()?;
    let provider = runtime.block_on(
        synthetic_born_provider_v1::SyntheticBornProviderV1::reopen_public_original_v1(
            &ready.provider_reopen,
            synthetic_provider_tls_v1::child_server_config()?,
            private_fixed_v2::child_original_cutoff()?,
        ),
    )?;
    let OwnerControl::AdmitFinancialContinuationV1 { record } = &ready.continuations[0].control
    else {
        return Err(Error::Authentication);
    };
    let operation = &record.terms.scope.delivery.submission_operation_id;
    let source = &record.terms.scope.delivery.provider;
    let adapter = wholepact_chain::ChainAdapter::testnet(
        &source.source_id,
        &source.endpoint,
        wholepact_chain::NetworkPolicy::default(),
    )?;
    if adapter.identity().trust_profile != source.trust_profile
        || provider.endpoint() != source.endpoint
    {
        return Err(Error::Authentication);
    }
    let mut backend =
        synthetic_born_submission_sink_v1::SyntheticFinancialSubmissionBackendV1::new(
            &provider, adapter,
        )?;
    let summary = financial_host_operation(B::PrivateWorkspaceReadFixed, || {
        host.verify_completed_private_financial_summary_v1(&ready.workspace, operation)
    })?;
    require_completed_original(&ready, &summary)?;
    if summary.next_delegation_attempt != 1 || summary.latest_requests.is_some() {
        return Err(Error::Authentication);
    }
    let server = witness
        .serve_committed_completed_dispatch_pair_v1()
        .map_err(|e| financial_witness_error(financial_diagnostic::FinancialStageV1::WitnessCompletedPairService, B::DeliveryHistoricalRead, e))?;
    let first = financial_host_operation(B::DeliveryHistoricalRead, || {
        host.read_original_financial_history_v1(
            &ready.workspace,
            &ready.continuations[0].account_id,
            &ready.continuations[0].operation_id,
        )
    })?;
    let second = financial_host_operation(B::DeliveryHistoricalRead, || {
        host.read_original_financial_history_v1(
            &ready.workspace,
            &ready.continuations[1].account_id,
            &ready.continuations[1].operation_id,
        )
    })?;
    if first.continuation_request() != &ready.continuations[0]
        || second.continuation_request() != &ready.continuations[1]
    {
        return Err(Error::Authentication);
    }
    drop(server);
    let first_index =
        usize::from(ready.continuations[1].account_id < ready.continuations[0].account_id);
    let server = witness
        .serve_committed_completed_dispatch_v1(&ready.continuations[first_index].operation_id)
        .map_err(|e| financial_witness_error(financial_diagnostic::FinancialStageV1::WitnessCompletedAccountService, B::DeliveryNativeAdmission, e))?;
    // Genuine A-only configured service produces one-sided admission. An error
    // is NOT absence: inspect both exact saved requests from full histories next.
    financial_stage(&scenario, FinancialBoundaryV1::DispatchAdmission)?;
    financial_diagnostic::reset_operation();
    let partial = runtime.block_on(host.dispatch_completed_private_financial_v1(
        &ready.workspace,
        "synthetic-financial-pair-one",
        [&first, &second],
        &mut backend,
        &wholepact_chain::SystemSubmissionClock,
    ));
    let expected_partial_diagnostic = financial_diagnostic::take_operation_failure();
    let reconciled = (|| -> Result<_> {
        if partial.is_ok() || !backend.no_private_submission_observed() {
            return Err(Error::Authentication);
        }
        financial_stage(
            &scenario,
            FinancialBoundaryV1::PartialAdmissionReconciliation,
        )?;
        drop(server);
        drop(first);
        drop(second);
        let server = witness
            .serve_committed_completed_dispatch_pair_v1()
            .map_err(|e| financial_witness_error(financial_diagnostic::FinancialStageV1::WitnessCompletedPairService, B::DeliveryHistoricalRead, e))?;
        let first = financial_host_operation(B::DeliveryHistoricalRead, || {
            host.read_original_financial_history_v1(
                &ready.workspace,
                &ready.continuations[0].account_id,
                &ready.continuations[0].operation_id,
            )
        })?;
        let second = financial_host_operation(B::DeliveryHistoricalRead, || {
            host.read_original_financial_history_v1(
                &ready.workspace,
                &ready.continuations[1].account_id,
                &ready.continuations[1].operation_id,
            )
        })?;
        let partial_summary = financial_host_operation(B::PrivateWorkspaceReadFixed, || {
            host.verify_completed_private_financial_summary_v1(&ready.workspace, operation)
        })?;
        require_completed_original(&ready, &partial_summary)?;
        if partial_summary.next_delegation_attempt != 2 {
            return Err(Error::Authentication);
        }
        let old_pair = partial_summary
            .latest_requests
            .ok_or(Error::Authentication)?;
        let histories = [&first, &second];
        let mut committed = 0;
        for (index, request) in old_pair.iter().enumerate() {
            let history = histories
                .iter()
                .find(|h| h.snapshot().account_id == request.account_id)
                .ok_or(Error::Authentication)?;
            let result = history
                .completed_dispatch_outcome(request)
                .map_err(|_| Error::Authentication)?;
            if (index == 0) != result.is_some()
                || request.context.attempt != 1
                || request.context.final_transaction_digest != ready.transaction_digest
            {
                return Err(Error::Authentication);
            }
            if let Some(admission) = result {
                if admission.expires_at_ms > ready.original_valid_until_ms {
                    return Err(Error::Authentication);
                }
                committed += 1;
            }
        }
        if committed != 1 || !backend.no_private_submission_observed() {
            return Err(Error::Authentication);
        }
        Ok((server, first, second, old_pair))
    })();
    if reconciled.is_err() && !FINANCIAL_FAILURE_EMITTED.load(Ordering::SeqCst) {
        financial_diagnostic::reset_operation();
        if let Some(candidate) = expected_partial_diagnostic {financial_diagnostic::capture_first(candidate);}
        promote_financial_failure(&reconciled);
    }
    let (server, first, second, old_pair) = reconciled?;
    // Only exact full-history reconciliation established this expected partial case.
    // It must never become the first failure of a later independent operation.
    drop(expected_partial_diagnostic);
    financial_host_operation(B::DeliveryNativeAdmission, || {
        host.require_stale_financial_dispatch_refused_v1(&ready.workspace, &old_pair[0])
    })?;
    financial_stage(&scenario, FinancialBoundaryV1::SavedTransactionDispatch)?;
    let report = financial_host_operation(B::DeliveryNativeAdmission, || {
        runtime.block_on(host.dispatch_completed_private_financial_v1(
            &ready.workspace,
            "synthetic-financial-pair-two",
            [&first, &second],
            &mut backend,
            &wholepact_chain::SystemSubmissionClock,
        ))
    })?;
    let received = backend.finish(&report)?;
    if !received.exact_saved_transaction_received
        || !received.received_once
        || !received.actual_tls_provider
        || received.public_network_settlement
        || report.descriptor.bytes_sha256 != ready.transaction_digest
        || report.descriptor.transaction_id != ready.transaction_id
        || report.attempt.number != 1
    {
        return Err(Error::Authentication);
    }
    let final_summary = financial_host_operation(B::PrivateWorkspaceReadFixed, || {
        host.verify_completed_private_financial_summary_v1(&ready.workspace, operation)
    })?;
    require_completed_original(&ready, &final_summary)?;
    if final_summary.next_delegation_attempt != 3 {
        return Err(Error::Authentication);
    }
    let final_pair = final_summary.latest_requests.ok_or(Error::Authentication)?;
    let final_first = financial_host_operation(B::DeliveryHistoricalRead, || {
        host.read_original_financial_history_v1(
            &ready.workspace,
            &ready.continuations[0].account_id,
            &ready.continuations[0].operation_id,
        )
    })?;
    let final_second = financial_host_operation(B::DeliveryHistoricalRead, || {
        host.read_original_financial_history_v1(
            &ready.workspace,
            &ready.continuations[1].account_id,
            &ready.continuations[1].operation_id,
        )
    })?;
    for (old, new) in old_pair.iter().zip(&final_pair) {
        let mut immutable = old.context.clone();
        immutable.attempt = 2;
        if new.context != immutable
            || new.context.final_transaction_digest != ready.transaction_digest
        {
            return Err(Error::Authentication);
        }
        let history = [&final_first, &final_second]
            .into_iter()
            .find(|h| h.snapshot().account_id == new.account_id)
            .ok_or(Error::Authentication)?;
        let admission = history
            .completed_dispatch_outcome(new)
            .map_err(|_| Error::Authentication)?
            .ok_or(Error::Authentication)?;
        if admission.expires_at_ms > ready.original_valid_until_ms
            || admission.request.context.attempt != 2
        {
            return Err(Error::Authentication);
        }
    }
    drop(server);
    drop(first);
    drop(second);
    drop(final_first);
    drop(final_second);
    drop(witness);
    drop(backend);
    runtime.block_on(provider.shutdown())?;
    drop(runtime);
    let completion = FinancialCompletionV1 {
        schema: 1,
        source_prefix_preserved: true,
        both_continuations_authenticated: true,
        both_results_before_process_death: true,
        exact_completed_reopen_after_death: true,
        completed_extraction_checkpoint_count: 1,
        dedicated_dispatch_admissions: 2,
        identical_saved_bytes_dispatched: true,
        partial_admission_reconciled: true,
        bounded_admission_retry_same_bytes: true,
        original_expiry_preserved: true,
        stale_head_refused: true,
        synthetic_backend_only: true,
        public_chain_verified: false,
    };
    // These values are emitted only after all concrete comparisons above. The
    // parent independently verifies child reap/group absence before reading them.
    write_record(&scenario, FINANCIAL_FINISHED, &completion)?;
    Ok(())
}

fn financial_dispatch_inputs(inputs: &mut Vec<Input<'static>>) {
    financial_owner_input(inputs);
    inputs.push(review("Read and mathematically verify only the saved original financial union and completed transaction"));
    financial_three_scope_retention_inputs(inputs);
    inputs.push(review(
        "Approve extract/read and retain exact complete transaction for this EXACT scope?",
    ));
    inputs.push(review("Approve copy exact retained transaction to the named local submission journal for this EXACT scope?"));
    inputs.push(review("DISPATCH EXACT SAVED TRANSACTION, attempt"));
}
fn financial_reader_inputs() -> Vec<Input<'static>> {
    let mut inputs = vec![
        Input::Text {
            prompt: "Storage passphrase: ",
            response: "synthetic-recovery-review-password",
        },
        Input::Text {
            prompt: "Original primary financial passphrase: ",
            response: "synthetic-recovery-review-password",
        },
        review("Authenticate the same final-v4 original workspace"),
    ];
    private_fixed_v2::session_inputs(&mut inputs, false);
    financial_audit_inputs(&mut inputs);
    for _ in 0..2 {
        financial_history_inputs(&mut inputs);
    }
    financial_dispatch_inputs(&mut inputs);
    for _ in 0..2 {
        financial_history_inputs(&mut inputs);
    }
    financial_audit_inputs(&mut inputs);
    financial_owner_input(&mut inputs);
    inputs.push(review(
        "Verify the saved original dispatch pair and perform one never-funded qualification probe",
    ));
    financial_dispatch_inputs(&mut inputs);
    financial_audit_inputs(&mut inputs);
    for _ in 0..2 {
        financial_history_inputs(&mut inputs);
    }
    inputs
}

#[test]
fn financial_retention_prompt_contract_is_exact_and_bounded() {
    let signed = "Approve retain exact usable signatures for this EXACT scope?";
    let producer = financial_producer_inputs();
    let reader = financial_reader_inputs();
    assert_eq!(producer.len(), 151);
    assert_eq!(reader.len(), 58);
    let signed_count = |inputs: &[Input<'_>]| {
        inputs.iter().filter(|input|
        matches!(input, Input::ExactReview { detail, approve: true } if *detail == signed)
    ).count()
    };
    // Two singleton intakes plus completion and completed audit's exact triples.
    assert_eq!(signed_count(&producer), 8);
    // Three completed audits plus two explicit dispatch attempts, no intake.
    assert_eq!(signed_count(&reader), 15);
    for make in [financial_audit_inputs, financial_dispatch_inputs] {
        let mut inputs = Vec::new();
        make(&mut inputs);
        assert!(inputs[2..5].iter().all(|input|
            matches!(input, Input::ExactReview { detail, approve: true } if *detail == signed)
        ));
    }
}

#[test]
#[ignore = "Explicit approved isolated Linux synthetic runner only; genuine financial sources, exact retained transaction and actual dedicated TLS"]
fn original_two_owner_financial_continuation_survives_process_death() {
    run_financial_lifecycle_v1().expect("exact saved original transaction dispatches after genuine producer death; synthetic backend only, no public settlement");
}
fn run_financial_lifecycle_v1() -> io::Result<()> {
    process_containment_v1::require_and_report_core_policy()?;
    let deadline = Instant::now() + WORKFLOW_LIMIT;
    let cutoff = monotonic_now_ns()?
        .checked_add(
            deadline
                .saturating_duration_since(Instant::now())
                .as_nanos()
                .try_into()
                .map_err(|_| invalid())?,
        )
        .ok_or_else(invalid)?;
    let mut public = FinancialPublicV1::pending();
    let mut root = Some(
        tempfile::Builder::new()
            .prefix(CHILD_TEMPORARY_PREFIX)
            .permissions(std::fs::Permissions::from_mode(0o700))
            .tempdir()?,
    );
    let workflow = (|| -> io::Result<()> {
        owned_test_process_group_v1::require_default_child_wait_policy()?;
        // One original TLS installation is retained across both processes. No
        // new test credential, trust root or endpoint is created on reopening.
        let tls =
            synthetic_provider_tls_v1::ChildTlsMaterialV1::prepare(root.as_ref().unwrap().path())?;
        let mut producer = private_workspace_stage_v1(
            root.take().unwrap(),
            Some(&tls),
            PrivateWorkspaceStageV1::FinancialProducer,
            &financial_producer_inputs(),
            deadline,
            cutoff,
        )?;
        public.producer_reaped =
            producer.process.direct_child == owned_test_process_group_v1::DirectChildV1::Reaped;
        public.producer_group_absent = producer.process.group_absence
            == owned_test_process_group_v1::GroupAbsenceV1::OriginalGroupAbsentObserved;
        root = producer.root.take();
        if producer.outcome.is_err()
            || !producer.process.verified()
            || producer.process.group_signal
                != owned_test_process_group_v1::GroupSignalV1::SentWhileLeaderOwned
            || !producer
                .process
                .status
                .as_ref()
                .is_some_and(|status| status.signal() == Some(libc::SIGKILL))
        {
            public.observe_failed_child(&producer);
            if producer.process.verified() {
                if let Some(root) = root.as_ref() {
                    match read_financial_transport_failure(root.path()) {
                        Ok(value) => public.transport_failure = value,
                        Err(_) => public.source_diagnostic_withheld = true,
                    }
                }
            }
            let boundary = if public.producer_reaped && public.producer_group_absent {
                root.as_ref()
                    .and_then(|root| last_financial_stage(root.path()).ok())
                    .unwrap_or(FinancialBoundaryV1::ProducerDeath)
            } else {
                FinancialBoundaryV1::ProducerDeath
            };
            public.fail(boundary, FinancialOutcomeV1::Unverified);
            return Err(invalid());
        }
        let ready = FinancialReadyV1::read_original(root.as_ref().ok_or_else(invalid)?.path())?;
        if Instant::now() >= deadline {
            public.fail(
                FinancialBoundaryV1::CompletedReopen,
                FinancialOutcomeV1::Expired,
            );
            return Err(invalid());
        }
        let mut reader = private_workspace_stage_v1(
            root.take().unwrap(),
            Some(&tls),
            PrivateWorkspaceStageV1::FinancialReader,
            &financial_reader_inputs(),
            deadline,
            cutoff,
        )?;
        public.reader_reaped =
            reader.process.direct_child == owned_test_process_group_v1::DirectChildV1::Reaped;
        public.reader_group_absent = reader.process.group_absence
            == owned_test_process_group_v1::GroupAbsenceV1::OriginalGroupAbsentObserved;
        root = reader.root.take();
        if reader.outcome.is_err()
            || !reader.process.verified()
            || !reader
                .process
                .status
                .as_ref()
                .is_some_and(|status| status.success())
            || Instant::now() >= deadline
        {
            public.observe_failed_child(&reader);
            let boundary = if public.reader_reaped && public.reader_group_absent {
                root.as_ref()
                    .and_then(|root| last_financial_stage(root.path()).ok())
                    .unwrap_or(FinancialBoundaryV1::ReaderReap)
            } else {
                FinancialBoundaryV1::ReaderReap
            };
            public.fail(boundary, FinancialOutcomeV1::Unverified);
            return Err(invalid());
        }
        let root_path = root.as_ref().ok_or_else(invalid)?.path();
        let after = FinancialReadyV1::read_original(root_path)?;
        if digest(&ready).map_err(|_| invalid())? != digest(&after).map_err(|_| invalid())? {
            return Err(invalid());
        }
        let completion: FinancialCompletionV1 = read_record(root_path, FINANCIAL_FINISHED)?;
        completion.apply_checked(&mut public)?;
        drop(tls);
        Ok(())
    })();
    if let Some(root) = root.take() {
        public.root_cleanup = match close_owned_temporary_root(root) {
            TemporaryRootCleanupV1::ClosedAndAbsenceVerified => "closed_absent",
            TemporaryRootCleanupV1::RetainedForUnverifiedProcess
            | TemporaryRootCleanupV1::CloseOrAbsenceUnverified => "unverified",
        };
    }
    if public.root_cleanup != "closed_absent" {
        public.fail(
            FinancialBoundaryV1::RootCleanup,
            FinancialOutcomeV1::Unverified,
        );
    }
    if workflow.is_err() && public.first_failure.is_none() {
        public.fail(
            FinancialBoundaryV1::OriginalPreparation,
            FinancialOutcomeV1::Unverified,
        );
    }
    public.emit_once()
}

#[test]
fn financial_diagnostic_requires_actual_stage_cleanup() {
    use financial_diagnostic::{FinancialDiagnosticV1,FinancialStageV1 as S,FinancialComponentV1 as C,FinancialErrorClassV1 as E,FinancialCommitStateV1 as K};
    let record=FinancialDiagnosticV1{schema:1,stage:S::ResultReceive,component:C::SignerBridge,error_class:E::Binding,commit_state:K::NotEstablished,current_timing:None,authority_call:None};
    for reader in [false,true] {
        for missing in 0..6 {
            let mut public=FinancialPublicV1::pending();
            public.first_failure=Some(if reader {FinancialBoundaryV1::SavedTransactionDispatch}else{FinancialBoundaryV1::SignatureAndIntake});
            public.root_cleanup=if missing==0 {"unverified"}else{"closed_absent"};
            public.producer_reaped=missing!=1;public.producer_group_absent=missing!=2;
            public.reader_reaped=missing!=3;public.reader_group_absent=missing!=4;
            public.financial_diagnostic=Some(record);
            public.withhold_unverified_diagnostics();
            let permitted=missing>=3 && (!reader || missing==5);
            assert_eq!(public.financial_diagnostic.is_some(),permitted);
        }
    }
}
