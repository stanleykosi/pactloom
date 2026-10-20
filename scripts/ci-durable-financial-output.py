#!/usr/bin/env python3
"""Closed public projection for the real, never-funded financial lifecycle.

No raw child text, transaction material, paths or exception strings are printed.
This is synthetic native integration, never evidence of public-chain settlement.
"""
import json
import importlib.util
import os
import pathlib
import selectors
import subprocess
import sys
import time

_spec = importlib.util.spec_from_file_location(
    "closed_existing_diagnostics",
    pathlib.Path(__file__).with_name("ci-synthetic-output.py"),
)
_diagnostics = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_diagnostics)

TEST = (
    "host::manual_enrollment::command::roster_publication_v2::"
    "sequential_construction_v3::qualification::durable_proposal_v1::"
    "delivery_admission_v2::durable_financial_dispatch_v1::"
    "original_two_owner_financial_continuation_survives_process_death"
)
PREFIX = b"CI_SYNTHETIC_DURABLE_FINANCIAL "
BOUNDARIES = frozenset(
    "OriginalPreparation ContinuationAdmission SignatureAndIntake "
    "FinalTransactionRetention ProducerDeath CompletedReopen DispatchAdmission "
    "PartialAdmissionReconciliation SavedTransactionDispatch ReaderReap RootCleanup".split()
)
OUTCOMES = frozenset("complete refused uncertain expired conflict unverified".split())
PROOFS = frozenset(
    "producer_reaped producer_group_absent reader_reaped reader_group_absent "
    "source_prefix_preserved both_continuations_authenticated "
    "both_results_before_process_death exact_completed_reopen_after_death "
    "identical_saved_bytes_dispatched partial_admission_reconciled "
    "bounded_admission_retry_same_bytes original_expiry_preserved stale_head_refused".split()
)
FIELDS = PROOFS | {
    "schema", "result", "first_failure", "boundary_outcome", "root_cleanup",
    "completed_extraction_checkpoint_count", "dedicated_dispatch_admissions",
    "synthetic_backend_only", "public_chain_verified",
    "source_failure_boundary", "source_failure_outcome",
    "failed_child_inputs_completed", "failed_child_inputs_expected",
    "private_fixed_primary", "source_diagnostic_withheld", "transport_failure", "financial_diagnostic", "progress_failure", "progress_timing",
}

READER_BOUNDARIES = frozenset("CompletedReopen DispatchAdmission PartialAdmissionReconciliation SavedTransactionDispatch ReaderReap".split())
FINANCIAL_STAGES = frozenset("NativeSourceOpen NativeHistoryRead NativeContinue NativeAdmit NativeAcquire NativeActivate NativeWalletPrepare NativeWalletObserve NativeSignPrepare NativeSign NativeReturnPrepare NativeHostPreparedWait NativeReturnApprove NativeReturnServe NativeReviewStage NativeResultRequest NativeAuthorityHistoryRead NativeFinancialHistoryRead NativeAuthorityAdmit NativeAuthorityAcquire NativeAuthorityActivate NativeAuthorityVerifyActive NativeWalletChain NativeWalletBirthday NativeWalletInitialize NativeWalletImport NativeWalletController NativeWalletVerify NativeWalletStatus NativeWalletMaterial NativeWalletSynchronize NativeWalletTicket NativeWalletReconcile LifecycleHarness WitnessHistoryService WitnessContinuationReview WitnessContinuationCommit WitnessSigningService WitnessCompletedPairService WitnessCompletedAccountService WitnessOriginalReopen WitnessOriginalPreserve WorkerCommand WorkerReply WorkerPhaseWait WorkerReview WorkerSourceOpen WorkerRequest WorkerReturn WorkerDrain InputValidation OriginalSource ReadConsent EffectConsent SourcePreparation RetentionContexts ContinuationBinding ResultPreview SignedRetentionApproval IntakeSetupApproval RetentionFreeze ResultReceive AuthenticatedIntake ResultFinishAcknowledgement UnionRetention TransactionCheckpoint CompletedVerification DispatchReview PairIntentRetention RetainedPairRead AdmissionFirst AdmissionSecond AdmissionReceiptRetention DispatchReverification BackendContext SavedTransactionHandoff DispatchOutcome FinancialHistory AuditSummary StaleRefusal Currentness ResultInstalledProviderVerification ResultHostPreparedWrite ResultReadyWait ResultFetchWrite ResultHeldRead ResultEvidenceValidation ResultPreviewMatch ResultCurrentProviderVerification ResultCurrentWrite ResultCurrentRead ResultCurrentMatch ResultFinishWrite ResultFinishRead ResultCurrentLock ResultCurrentPeer ResultReadyMatch ResultHeldMatch ResultFinishMatch".split())
FINANCIAL_COMPONENTS = frozenset("Store Journal StorageSecurity Signer Wallet Sync DurableConstruction WalletKeyUse Authority Host Engine SignerBridge Chain".split())
FINANCIAL_COMMIT_STATES = frozenset("NotEstablished IntakeCommitted OutcomeUncertain".split())
FINANCIAL_ERRORS = frozenset("StoreDatabase StoreEncoding StorePoisoned StoreIdempotencyConflict StoreRevisionConflict StoreNotFound StoreAlreadyExists StoreInvalidInput StoreUnsupportedSchema StoreRecoveryRequired StoreWriterEpochMismatch StoreLiveAuthorizationExists StoreInputReserved StoreResourceExhausted StoreBudgetExceeded StoreInvalidTransition StoreFile JournalStorage JournalDatabase JournalPermission JournalExpired JournalRecoveryRequired JournalUnsupportedSchema JournalOfflineHistoryUnsupported JournalNamedRecipientHistoryUnsupported JournalConstructionHistoryUnsupported JournalInvalidBinding JournalConflict JournalNotFound JournalLiveAuthorization JournalInputReserved JournalBudgetExceeded JournalLimit StorageUnsupportedPlatform StorageQuarantinedDatabase StorageRecoveredGeneration StorageGenerationArchive StorageUninitializedDatabase StorageUnsafePath StorageAlreadyExists StorageMissingDatabase StoragePlaintextRefused StorageUnqualifiedRuntime StorageAuthenticationFailed StorageDatabase StorageIo StorageSnapshotLimit StorageSourceChanged Unavailable PeerLifetimeUnavailable Io InvalidData Crypto BackupRequired AlreadyOpen ReviewMismatch ConsentJournal Store Limit CompleteOriginRecoveryUnavailable AuthorityInvalidBinding AuthorityPermission AuthorityStaleHead AuthorityConflict AuthorityInactive AuthorityRecoveryRequired AuthorityExpired AuthorityPolicyDenied AuthorityBudgetExceeded AuthorityInputReserved AuthorityObligationReserved AuthorityLimit AuthorityStorage AuthorityCorruptHistory AuthorityPermanentStopUnavailable AuthorityOfflineHistoryUnsupported AuthorityConstructionHistoryUnsupported AuthorityUnsupportedVersion AuthorityAuthentication AuthorityUncertain AuthorityResolutionUnavailable AuthoritySessionRequired AuthoritySessionPending WalletStorage WalletAccountScope WalletAccountMismatch WalletIncompleteSync WalletUnsupportedProfile WalletChainMismatch WalletInsufficientFunds WalletInvalidRequest WalletMissingWitness WalletInvalidNote WalletScan WalletTransport SyncAccessDenied SyncInvalidRequest SyncInterrupted SyncReconciliationRequired SyncInvalidResponse SyncResourceLimit SyncNoCurrentObservation ChainInvalidConfiguration ChainWrongNetwork ChainUnsupportedProxyConfiguration ChainWrongBranch ChainStaleChain ChainContradictoryChain ChainTimeout ChainTransportUnavailable ChainObservationInterrupted ChainMissingAncestryEvidence ChainNotObserved ChainResourceLimit ChainMalformedEvidence ChainUnsupportedCapability ChainBackendFailure ChainClockUnavailable ChainIdempotencyConflict ChainJournalFailure ChainSubmissionNotAuthorized ChainSubmissionExpiryMargin ChainObligationConflict ChainSubmissionOutcomeUnrecorded ChainSubmissionRetentionUncertain DurableInvalid DurableBinding DurableStale DurableStorage KeyUsePermission KeyUsePolicy KeyUseSelectionExpired KeyUseStorage KeyUseRecoveryRequired KeyUseStateChanged KeyUseExpiry StaleHead Inactive PolicyDenied BudgetExceeded InputReserved ObligationReserved CorruptHistory SessionRequired SessionPending Permission Binding Conflict Missing RecoveryRequired Verification Storage ResourceLimit Expired Uncertain Unsupported Authentication Terminal Invalid Locked Ipc Journal Authority Wallet SignerOriginUnavailable DurableProposalConflict DurableProposalRecoveryRequired SignaturesIncomplete RetentionDenied RetentionConflict OriginalIntentMissing RetentionRecoveryRequired SubmissionUnresolved FinancialOutcomeReconciliation RevisionConflict Timeout Interrupted TransportUnavailable WrongNetwork WrongBranch StaleChain ContradictoryChain BackendFailure ClockUnavailable Other FrameUnclassified FrameDeadline FrameEof FrameCredentialsMissing FrameCredentialsMismatch FrameAncillaryRejected FrameTruncated FramePeerNotLive FrameCurrentCheck FrameIo FrameLimit FrameInvalid FrameInvalidBudget".split())

AUTHORITY_STAGES = frozenset("CallerDeadline ExchangeDeadline SourceCallback SnapshotConnect SnapshotHandshake SnapshotPeerBinding SnapshotRequestBuild SnapshotRequestWrite SnapshotResponseRead SnapshotResponse SnapshotValidation PageConnect PageHandshake PagePeerBinding PageRequestBuild PageRequestWrite PageResponseRead PageResponse PageValidation EventReplay FinalValidation Bounds AdmissionRequestValidation AdmissionBinding AdmissionConnect AdmissionHandshake AdmissionPeerBinding AdmissionRequestBuild AdmissionRequestWrite AdmissionResponseRead AdmissionResponse AdmissionSnapshotValidation AdmissionCommittedHeadValidation AdmissionFinalValidation FlowRequestValidation FlowBinding FlowSession FlowConnect FlowHandshake FlowPeerBinding FlowRequestBuild FlowRequestWrite FlowResponseRead FlowResponse FlowSnapshotValidation FlowReceiptValidation FlowCommittedHeadValidation FlowFinalValidation".split())
AUTHORITY_CHECK_SITES = frozenset("ReplayInitial ReplayAfterSnapshot ReplayBeforePage ReplayAfterPage ReplayFinal ExchangeInitial BeforeConnect AfterConnect BeforeHandshakeIo AfterHandshake AfterPeerBinding AfterRequestBuild BeforeRequestWrite AfterRequestWrite AfterResponseRead".split())
AUTHORITY_CHECKPOINTS = frozenset("EntryDeadline DeadlineSelection ConnectRemaining BeforeCallback Callback AfterCallback Operation Validation".split())
AUTHORITY_LIMITS = frozenset("Caller Exchange".split())
AUTHORITY_COST_FIELDS = frozenset("callback_calls callback_us callback_max_us connect_calls connect_us handshake_calls handshake_us frame_write_calls frame_write_us frame_read_calls frame_read_us".split())
AUTHORITY_OPTIONAL_MICROS = frozenset("selected_budget_us caller_remaining_at_failure_us selected_remaining_at_failure_us exchange_elapsed_us".split())
AUTHORITY_FIELDS = AUTHORITY_OPTIONAL_MICROS | {"stage", "check_site", "checkpoint", "selected_limit", "exchange_cost", "clamped", "incomplete", "pre_budget_callback_calls", "pre_budget_callback_us"}

def validate_authority_call(value):
    if type(value) is not dict or set(value) != AUTHORITY_FIELDS:
        raise ValueError()
    for key, values, optional in (("stage", AUTHORITY_STAGES, False), ("check_site", AUTHORITY_CHECK_SITES, True), ("checkpoint", AUTHORITY_CHECKPOINTS, False), ("selected_limit", AUTHORITY_LIMITS, True)):
        v = value[key]
        if optional and v is None:
            continue
        if type(v) is not str or v not in values:
            raise ValueError()
    for key in AUTHORITY_OPTIONAL_MICROS | {"pre_budget_callback_us", "pre_budget_callback_calls"}:
        v = value[key]
        if key in AUTHORITY_OPTIONAL_MICROS and v is None:
            continue
        if type(v) is not int or not 0 <= v <= (1 if key == "pre_budget_callback_calls" else 600000000):
            raise ValueError()
    for key in ("clamped", "incomplete"):
        if type(value[key]) is not bool:
            raise ValueError()
    cost = value["exchange_cost"]
    if cost is not None:
        if type(cost) is not dict or set(cost) != AUTHORITY_COST_FIELDS:
            raise ValueError()
        for key, v in cost.items():
            if type(v) is not int or not 0 <= v <= (1000000 if key.endswith("_calls") else 600000000):
                raise ValueError()
    return value

PROGRESS_PHASES = "SourceOpen ReadContinue Continue Admission ReadAcquire Acquire ReadActivate Activate Wallet ReadSign Sign".split()
PROGRESS_WINDOWS = [(owner, phase) for owner in (1, 2) for phase in PROGRESS_PHASES] + [(0,"PairHistory"),(1,"Return"),(2,"Return"),(0,"FinalRetention"),(0,"Shutdown")]
PROGRESS_CALLS = frozenset("Begin BeginFinancial ReadRequest WitnessStart ReadHistory BindHistory AwaitReturn WaitPhase Approve SendAdmission WitnessFinish StartServer DropServer ReadPeer Intake Preserve Complete Shutdown".split())
# These are last-observed native stages, never a claim of current execution or cause.
PROGRESS_NATIVE_STAGES = frozenset("SourceOpen HistoryRead Continue Admit Acquire Activate WalletPrepare WalletObserve SignPrepare Sign ReturnPrepare HostPreparedWait ReturnApprove ReturnServe ReviewStage ResultRequest AuthorityHistoryRead FinancialHistoryRead AuthorityAdmit AuthorityAcquire AuthorityActivate AuthorityVerifyActive WalletChain WalletBirthday WalletInitialize WalletImport WalletController WalletVerify WalletStatus WalletMaterial WalletSynchronize WalletTicket WalletReconcile".split())
def validate_progress_failure(record):
    if type(record) is not dict or set(record) != {"reason","last"}:
        raise ValueError()
    if type(record["reason"]) is not str or record["reason"] not in {"PhaseDeadline","InvalidProgress","GlobalDeadline"}:
        raise ValueError()
    last = record["last"]
    if last is None:
        if record["reason"] == "PhaseDeadline":
            raise ValueError()
        return
    if type(last) is not dict or set(last) != {"window","owner","phase","call","last_native"}:
        raise ValueError()
    window = last["window"]
    if type(window) is not int or not 0 <= window < len(PROGRESS_WINDOWS):
        raise ValueError()
    if type(last["owner"]) is not int or type(last["phase"]) is not str or (last["owner"],last["phase"]) != PROGRESS_WINDOWS[window]:
        raise ValueError()
    if type(last["call"]) is not str or last["call"] not in PROGRESS_CALLS:
        raise ValueError()
    job = last["last_native"]
    if job is not None:
        if type(job) is not dict or set(job) != {"owner","job_id","sequence","stage"}:
            raise ValueError()
        if type(job["owner"]) is not int or job["owner"] not in (1,2):
            raise ValueError()
        for key in ("job_id","sequence"):
            if type(job[key]) is not int or not 1 <= job[key] <= (16777215 if key == "sequence" else 4294967295):
                raise ValueError()
        if type(job["stage"]) is not str or job["stage"] not in PROGRESS_NATIVE_STAGES:
            raise ValueError()

def validate_progress_timing(record, progress):
    keys = {"elapsed_before_first_window_ms", "completed_window_elapsed_ms", "current_window_elapsed_ms", "total_elapsed_ms", "clamped"}
    if type(record) is not dict or set(record) != keys or type(record["clamped"]) is not bool:
        raise ValueError()
    def bounded(value):
        return type(value) is int and 0 <= value <= 900_000
    before, current = record["elapsed_before_first_window_ms"], record["current_window_elapsed_ms"]
    completed, total = record["completed_window_elapsed_ms"], record["total_elapsed_ms"]
    if not bounded(total) or type(completed) is not list or len(completed) > 26 or not all(bounded(v) for v in completed):
        raise ValueError()
    if record["clamped"] and total != 900_000:
        raise ValueError()
    if before is None and current is None:
        if completed:
            raise ValueError()
    elif not bounded(before) or not bounded(current) or before + current + sum(completed) != total:
        raise ValueError()
    if progress is not None:
        last = progress["last"]
        if (last is None and before is not None) or (last is not None and (before is None or len(completed) != last["window"])):
            raise ValueError()

def validate_financial_diagnostic(record):
    if type(record) is not dict or set(record) != {"schema", "stage", "component", "error_class", "commit_state", "current_timing", "authority_call"}:
        raise ValueError()
    if type(record["schema"]) is not int or record["schema"] != 1:
        raise ValueError()
    for key, values in (("stage", FINANCIAL_STAGES), ("component", FINANCIAL_COMPONENTS), ("error_class", FINANCIAL_ERRORS), ("commit_state", FINANCIAL_COMMIT_STATES)):
        if type(record[key]) is not str or record[key] not in values:
            raise ValueError()
    timing = record["current_timing"]
    if timing is not None:
        stages = {"ResultCurrentLock", "ResultCurrentPeer", "ResultCurrentProviderVerification", "ResultCurrentWrite", "ResultCurrentRead", "ResultCurrentMatch"}
        if record["component"] != "SignerBridge" or record["stage"] not in stages:
            raise ValueError()
        required = {"budget_ms", "roundtrip_elapsed_ms"}
        optional = {"provider_elapsed_ms", "remaining_before_write_ms", "remaining_before_read_ms"}
        if type(timing) is not dict or set(timing) != required | optional:
            raise ValueError()
        for key in required | optional:
            value = timing[key]
            if key in optional and value is None:
                continue
            if type(value) is not int or not 0 <= value <= 2001:
                raise ValueError()
    authority_call = record["authority_call"]
    if authority_call is not None:
        if timing is not None or record["stage"] not in {"NativeAuthorityAdmit", "NativeAuthorityAcquire", "NativeAuthorityActivate", "NativeAuthorityVerifyActive"}:
            raise ValueError()
        validate_authority_call(authority_call)
    return record


def unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError()
        result[key] = value
    return result


def validate(row):
    if not isinstance(row, dict) or set(row) != FIELDS:
        raise ValueError()
    if type(row["schema"]) is not int or row["schema"] != 4:
        raise ValueError()
    if row["result"] not in ("passed", "failed"):
        raise ValueError()
    if row["first_failure"] is not None and row["first_failure"] not in BOUNDARIES:
        raise ValueError()
    if row["boundary_outcome"] is not None and row["boundary_outcome"] not in OUTCOMES:
        raise ValueError()
    if (row["first_failure"] is None) != (row["boundary_outcome"] is None):
        raise ValueError()
    if row["root_cleanup"] not in ("closed_absent", "unverified"):
        raise ValueError()
    for key in PROOFS | {"synthetic_backend_only", "public_chain_verified", "source_diagnostic_withheld"}:
        if type(row[key]) is not bool:
            raise ValueError()
    for key, maximum in (("completed_extraction_checkpoint_count", 1), ("dedicated_dispatch_admissions", 2)):
        if type(row[key]) is not int or not 0 <= row[key] <= maximum:
            raise ValueError()
    if not row["synthetic_backend_only"] or row["public_chain_verified"]:
        raise ValueError()
    boundary, outcome = row["source_failure_boundary"], row["source_failure_outcome"]
    if (boundary is None) != (outcome is None):
        raise ValueError()
    if boundary is not None:
        if (
            type(boundary) is not str or boundary not in _diagnostics.DURABLE_DELIVERY_BOUNDARIES
            or type(outcome) is not str or outcome not in _diagnostics.OUTCOMES
            or outcome in ("Begin", "Complete")
        ):
            raise ValueError()
    completed, expected = row["failed_child_inputs_completed"], row["failed_child_inputs_expected"]
    if (completed is None) != (expected is None):
        raise ValueError()
    if completed is not None and (
        type(completed) is not int or type(expected) is not int
        or not 0 <= completed <= expected <= 512 or expected == 0
    ):
        raise ValueError()
    primary = row["private_fixed_primary"]
    if primary is not None:
        _diagnostics.private_fixed_object(primary, _diagnostics.PRIVATE_FIXED_PRIMARY_FIELDS)
        _diagnostics.private_fixed_primary(primary)
    transport = row["transport_failure"]
    if transport is not None:
        if type(transport) is not dict or set(transport) != {"chain", "provider"}:
            raise ValueError()
        counters = {
            "chain": set("connect_including_tls readiness request body_drain unary_status".split()),
            "provider": set("accepted_connections accept_errors handshake_successes handshake_errors handshake_timeouts connection_limit_stops connection_deadline_stops requests denied request_limit_denials request_deadline_denials request_shape_denials body_read_errors body_read_timeouts frame_denials method_denials replies".split()),
        }
        for group, names in counters.items():
            flags = {"deadline_elapsed", "server_finished", "clamped"} if group == "provider" else set()
            value = transport[group]
            if type(value) is not dict or set(value) != names | flags:
                raise ValueError()
            if any(type(value[name]) is not int or not 0 <= value[name] <= 1_000_000 for name in names):
                raise ValueError()
            if any(type(value[name]) is not bool for name in flags):
                raise ValueError()
        if row["first_failure"] != "OriginalPreparation":
            raise ValueError()
    financial = row["financial_diagnostic"]
    if financial is not None:
        validate_financial_diagnostic(financial)
    progress = row["progress_failure"]
    if progress is not None:
        validate_progress_failure(progress)
        if row["first_failure"] in READER_BOUNDARIES:
            raise ValueError()
    timing = row["progress_timing"]
    if timing is not None:
        validate_progress_timing(timing, progress)
        if row["first_failure"] in READER_BOUNDARIES:
            raise ValueError()
    observed = any(value is not None for value in (boundary, outcome, completed, expected, primary, transport, financial, progress, timing))
    if observed and (
        row["result"] != "failed" or row["first_failure"] is None
        or row["root_cleanup"] != "closed_absent"
        or not row["producer_reaped"] or not row["producer_group_absent"]
    ):
        raise ValueError()
    if observed and row["first_failure"] in READER_BOUNDARIES and (not row["reader_reaped"] or not row["reader_group_absent"]):
        raise ValueError()
    if row["result"] == "passed":
        if (
            not all(row[key] for key in PROOFS)
            or row["first_failure"] is not None
            or row["root_cleanup"] != "closed_absent"
            or row["completed_extraction_checkpoint_count"] != 1
            or row["dedicated_dispatch_admissions"] != 2
            or observed or row["source_diagnostic_withheld"]
        ):
            raise ValueError()
    return row


def run(executable):
    # Rust's exact selector plus the mandatory validated completion summary
    # fail closed if the test is absent or ignored. Do not capture an unbounded
    # catalogue merely to establish a selector already fixed in this script.
    process = subprocess.Popen(
        [executable, TEST, "--exact", "--ignored", "--nocapture", "--test-threads=1"],
        stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
    )
    row = None
    pending = bytearray()
    overlong = False
    deadline = time.monotonic() + 1800
    status = None
    try:
        with selectors.DefaultSelector() as selected:
            selected.register(process.stdout, selectors.EVENT_READ)
            while selected.get_map():
                if time.monotonic() >= deadline:
                    raise TimeoutError()
                for key, _ in selected.select(timeout=1):
                    chunk = os.read(key.fileobj.fileno(), 4096)
                    if not chunk:
                        selected.unregister(key.fileobj)
                        continue
                    for byte in chunk:
                        if byte == 10:
                            if overlong:
                                raise ValueError()
                            line = bytes(pending).rstrip(b"\r")
                            harness_prefix = ("test " + TEST + " ... ").encode()
                            if line.startswith(harness_prefix):
                                line = line[len(harness_prefix):]
                            if PREFIX in line:
                                if overlong or row is not None or not line.startswith(PREFIX):
                                    raise ValueError()
                                row = validate(json.loads(
                                    line[len(PREFIX):],
                                    object_pairs_hook=unique_object,
                                ))
                            pending.clear()
                            overlong = False
                        elif len(pending) < 4096:
                            pending.append(byte)
                        else:
                            overlong = True
            if overlong or PREFIX in pending:
                raise ValueError()
        status = process.wait(timeout=10)
    finally:
        if status is None:
            process.kill()
            process.wait(timeout=10)
            print("CI_FINANCIAL_RESULT cleanup_unverified=true passed=false", flush=True)
    if row is not None and (status == 0 or row["result"] != "passed"):
        print(PREFIX.decode() + json.dumps(row, sort_keys=True, separators=(",", ":")), flush=True)
    if status != 0 or row is None or row["result"] != "passed":
        raise RuntimeError()
    print("CI_FINANCIAL_RESULT passed=true public_chain_verified=false", flush=True)


if __name__ == "__main__":
    try:
        if len(sys.argv) != 2:
            raise ValueError()
        exe = pathlib.Path(sys.argv[1]).resolve(strict=True)
        target = pathlib.Path(os.environ["CARGO_TARGET_DIR"]).resolve(strict=True)
        if not exe.is_file() or not exe.is_relative_to(target):
            raise ValueError()
        run(str(exe))
    except Exception:
        print("CI_FINANCIAL_RESULT passed=false details_withheld=true", flush=True)
        sys.exit(1)
