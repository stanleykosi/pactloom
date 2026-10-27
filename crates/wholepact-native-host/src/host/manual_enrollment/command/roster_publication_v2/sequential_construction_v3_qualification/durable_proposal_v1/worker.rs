//! Separate finite never-funded native worker for durable qualification.
//! Historical setup uses real birth/roster controllers only. There are no V3
//! common-context, construction, consumed-owner or named payment variants.
use super::safe_diagnostics_v1::{self as diagnostic, Boundary as B, Outcome};
use sha2::{Digest, Sha256};
use std::{
    path::PathBuf,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
        mpsc::{self, Receiver, Sender},
    },
    thread::{self, JoinHandle},
    time::{Duration, Instant},
};
use wholepact_authority::{
    AccountPolicy, OwnerControlRequest, native_witness_owner::EphemeralWitnessOriginV1,
};
use wholepact_core::born_recipient_policy_v2::{
    BornConstructionRecipientPolicyV2, BornOriginalLimitsV2, BornOwnReturnRuleV2,
    BornRecipientLimitV2,
};
use wholepact_signer::authority_bridge::{
    AuthorizationCommit,
    durable_construction_v1::{
        DurableConstructionCaptureRequestV1, DurableConstructionRedisclosureRequestV1,
    },
    durable_review_ipc_v1::DurableReviewDeliveryRequestV1,
    ipc::HistoryRequest,
    preconstruction_ipc::PreconstructionRequest,
};
use wholepact_signer::native_ui::synthetic_born_joined_qualification::{
    DurableAcquireReplyLossV1, DurableAdmissionCallFailureV1, DurableAdmissionCallbackStageV1,
    DurableAdmissionDispatchFailureV1, DurableAdmissionDispatchStageV1,
    DurableAdmissionHistoryFailureV1, DurableAdmissionPreparationFailureV1,
    DurableAdmissionPreparationStageV1, DurableFlowFailureV1, DurableFlowResultV1,
    DurableNativeEntryFailureV1, DurableNativeEntryStageV1, DurableNativeRecordsV1,
    EphemeralAcknowledgedBornV1, EphemeralClosedDeliveryNativeV3, EphemeralDurableDeliveryNativeV2,
    EphemeralDurableNativeV1, EphemeralExportedBirthV1, EphemeralFirstAnchorIntentV1,
    EphemeralFirstAnchorPublicationV1, EphemeralOriginalRosterIntentV1, EphemeralPendingBornV1,
    EphemeralRosterPublicationV1, OriginalBirthSetupV1,
};
use wholepact_signer_origin::{
    InstalledSignerProvider, PairScope,
    manual::{HostManualEnrollmentIntent, HostManualEnrollmentRequest},
    manual_roster_v2::{
        HostManualRosterEnrollmentIntentV2, HostManualRosterEnrollmentRequestV2,
        HostManualRosterPublicationRequestV2,
    },
};
type Result<T> = std::result::Result<T, &'static str>;
fn signer_error(error: wholepact_signer::Error, label: &'static str) -> &'static str {
    diagnostic::emit(B::SignerPollTerminal, diagnostic::signer_error(&error));
    label
}
// Capture only the actual failed command/job; the financial producer owns the
// single public promotion after its original error is returned and cleanup runs.
fn financial_signer_error(
    error: wholepact_signer::Error,
    label: &'static str,
    stage: crate::host::financial_diagnostics_v1::FinancialStageV1,
    detail: Option<wholepact_signer::native_ui::synthetic_born_joined_qualification::FinancialNativeDiagnosticV1>,
) -> &'static str {
    use crate::host::financial_diagnostics_v1 as f;
    if let Some(detail) = detail {
        f::native_job(detail);
    } else {
        f::signer(stage, f::FinancialCommitStateV1::OutcomeUncertain, &error);
    }
    signer_error(error, label)
}
// Same-result observation at the actual new production command boundary.
// Lower native/Bridge observations retain precedence; no private text is emitted.
fn closed_delivery_error(error: wholepact_signer::Error, boundary: B) -> wholepact_signer::Error {
    diagnostic::emit_delivery_observation(boundary, diagnostic::signer_error(&error));
    error
}
fn durable_flow_error(failure: DurableFlowFailureV1, label: &'static str) -> &'static str {
    // The original fixture Error controls the unchanged terminal mapping.
    // Writer reconciliation additionally retains inert evidence through its
    // already-required entry drain before this single emission.
    if let Some(observed) = failure.diagnostic() {
        diagnostic::emit_durable_flow(observed);
    }
    signer_error(failure.into_error(), label)
}
fn durable_entry_error(failure: DurableNativeEntryFailureV1) -> &'static str {
    use DurableNativeEntryStageV1 as S;
    let boundary = match failure.stage() {
        S::NativeOwnerCheck => B::DurableEntryNativeOwnerCheck,
        S::VaultOpen => B::DurableEntryVaultOpen,
        S::RetainedEnrollment => B::DurableEntryRetainedEnrollment,
        S::OriginalCommit => B::DurableEntryOriginalCommit,
        S::JournalOpen => B::DurableEntryJournalOpen,
        S::SourceCheck => B::DurableEntrySourceCheck,
        S::RuntimeActivation => B::DurableEntryRuntimeActivation,
        S::WorkerResult => B::DurableEntryWorkerResult,
        S::EndpointCreate => B::DurableEntryEndpointCreate,
        S::EndpointBind => B::DurableEntryEndpointBind,
        S::EndpointPublish => B::DurableEntryEndpointPublish,
        S::PostEndpointSourceCheck => B::DurableEntryPostEndpointSourceCheck,
        S::FixturePreflight => B::DurableEntryFixturePreflight,
        S::FixturePostActivation => B::DurableEntryFixturePostActivation,
    };
    let error = failure.into_error();
    diagnostic::emit(boundary, diagnostic::signer_error(&error));
    signer_error(error, "fresh durable original entry")
}
// Diagnostic routing only; this flag never participates in permission or IO.
fn checked_authority_boundary(
    stage: wholepact_authority::transport::history_diagnostics_v1::CheckedHistoryStageV1,
    admission: bool,
) -> Option<B> {
    use wholepact_authority::transport::history_diagnostics_v1::CheckedHistoryStageV1 as S;
    Some(match stage {
        S::CallerDeadline => {
            if admission {
                B::SignerAdmissionCallCallerDeadline
            } else {
                B::SignerAdmissionHistoryCallerDeadline
            }
        }
        S::ExchangeDeadline => {
            if admission {
                B::SignerAdmissionCallExchangeDeadline
            } else {
                B::SignerAdmissionHistoryExchangeDeadline
            }
        }
        S::SourceCallback => {
            if admission {
                B::SignerAdmissionCallSourceCallback
            } else {
                B::SignerAdmissionHistorySourceCallback
            }
        }
        S::SnapshotConnect => B::SignerAdmissionHistorySnapshotConnect,
        S::SnapshotHandshake => B::SignerAdmissionHistorySnapshotHandshake,
        S::SnapshotPeerBinding => B::SignerAdmissionHistorySnapshotPeerBinding,
        S::SnapshotRequestBuild => B::SignerAdmissionHistorySnapshotRequestBuild,
        S::SnapshotRequestWrite => B::SignerAdmissionHistorySnapshotRequestWrite,
        S::SnapshotResponseRead => B::SignerAdmissionHistorySnapshotResponseRead,
        S::SnapshotResponse => B::SignerAdmissionHistorySnapshotResponse,
        S::SnapshotValidation => B::SignerAdmissionHistorySnapshotValidation,
        S::PageConnect => B::SignerAdmissionHistoryPageConnect,
        S::PageHandshake => B::SignerAdmissionHistoryPageHandshake,
        S::PagePeerBinding => B::SignerAdmissionHistoryPagePeerBinding,
        S::PageRequestBuild => B::SignerAdmissionHistoryPageRequestBuild,
        S::PageRequestWrite => B::SignerAdmissionHistoryPageRequestWrite,
        S::PageResponseRead => B::SignerAdmissionHistoryPageResponseRead,
        S::PageResponse => B::SignerAdmissionHistoryPageResponse,
        S::PageValidation => B::SignerAdmissionHistoryPageValidation,
        S::EventReplay => B::SignerAdmissionHistoryEventReplay,
        S::FinalValidation => B::SignerAdmissionHistoryFinalValidation,
        S::Bounds => {
            if admission {
                B::SignerAdmissionCallBounds
            } else {
                B::SignerAdmissionHistoryBounds
            }
        }
        S::AdmissionRequestValidation => B::SignerAdmissionCallRequestValidation,
        S::AdmissionBinding => B::SignerAdmissionCallBinding,
        S::AdmissionConnect => B::SignerAdmissionCallConnect,
        S::AdmissionHandshake => B::SignerAdmissionCallHandshake,
        S::AdmissionPeerBinding => B::SignerAdmissionCallPeerBinding,
        S::AdmissionRequestBuild => B::SignerAdmissionCallRequestBuild,
        S::AdmissionRequestWrite => B::SignerAdmissionCallRequestWrite,
        S::AdmissionResponseRead => B::SignerAdmissionCallResponseRead,
        S::AdmissionResponse => B::SignerAdmissionCallResponse,
        S::AdmissionSnapshotValidation => B::SignerAdmissionCallSnapshotValidation,
        S::AdmissionCommittedHeadValidation => B::SignerAdmissionCallCommittedHeadValidation,
        S::AdmissionFinalValidation => B::SignerAdmissionCallFinalValidation,
        S::FlowRequestValidation
        | S::FlowBinding
        | S::FlowSession
        | S::FlowConnect
        | S::FlowHandshake
        | S::FlowPeerBinding
        | S::FlowRequestBuild
        | S::FlowRequestWrite
        | S::FlowResponseRead
        | S::FlowResponse
        | S::FlowSnapshotValidation
        | S::FlowReceiptValidation
        | S::FlowCommittedHeadValidation
        | S::FlowFinalValidation => return None,
    })
}
fn durable_admission_history_error(failure: DurableAdmissionHistoryFailureV1) {
    use wholepact_authority::transport::history_diagnostics_v1::CheckedHistoryIoKindV1 as I;
    let Some(boundary) = checked_authority_boundary(failure.stage(), false) else {
        return;
    };
    let io_boundary = failure.io_kind().map(|kind| match kind {
        I::Timeout => B::SignerAdmissionHistoryIoTimeout,
        I::Closed => B::SignerAdmissionHistoryIoClosed,
        I::Refused => B::SignerAdmissionHistoryIoRefused,
        I::Other => B::SignerAdmissionHistoryIoOther,
    });
    diagnostic::emit_history_measurement(failure.measurement());
    let (error, callback_error) = failure.into_errors();
    diagnostic::emit(boundary, diagnostic::authority_error(&error));
    if let Some(boundary) = io_boundary {
        diagnostic::emit(boundary, diagnostic::authority_error(&error));
    }
    if let Some(error) = callback_error {
        diagnostic::emit(
            B::SignerAdmissionHistoryCallbackError,
            diagnostic::signer_error(&error),
        );
    }
}
fn durable_admission_error(mut failure: DurableAdmissionPreparationFailureV1) -> &'static str {
    if let Some(history) = failure.take_history_failure() {
        durable_admission_history_error(history);
    }
    use DurableAdmissionPreparationStageV1 as S;
    let boundary = match failure.stage() {
        S::FixtureState => B::SignerAdmissionFixtureState,
        S::Source => B::SignerAdmissionSource,
        S::History => B::SignerAdmissionHistory,
        S::RetainedIntent => B::SignerAdmissionRetainedIntent,
        S::Terms => B::SignerAdmissionTerms,
        S::RequestBuilder => B::SignerAdmissionRequestBuilder,
        S::ExactRequest => B::SignerAdmissionExactRequest,
        S::LiveInterval => B::SignerAdmissionLiveInterval,
        S::LocalIntent => B::SignerAdmissionLocalIntent,
        S::IntentDisplay => B::SignerAdmissionIntentDisplay,
        S::ReviewCustody => B::SignerAdmissionReviewCustody,
        S::ReviewDisplay => B::SignerAdmissionReviewDisplay,
        S::NativeStage => B::SignerAdmissionNativeStage,
        S::WorkerCompletion => B::SignerAdmissionWorkerCompletion,
    };
    let error = failure.into_error();
    diagnostic::emit(boundary, diagnostic::signer_error(&error));
    signer_error(error, "source-bound exact durable admission preparation")
}
fn durable_admission_call_error(failure: DurableAdmissionCallFailureV1) {
    use wholepact_authority::transport::history_diagnostics_v1::CheckedHistoryIoKindV1 as I;
    let Some(boundary) = checked_authority_boundary(failure.stage(), true) else {
        return;
    };
    let io_boundary = failure.io_kind().map(|kind| match kind {
        I::Timeout => B::SignerAdmissionCallIoTimeout,
        I::Closed => B::SignerAdmissionCallIoClosed,
        I::Refused => B::SignerAdmissionCallIoRefused,
        I::Other => B::SignerAdmissionCallIoOther,
    });
    let callback_boundary = failure.callback_stage().map(|stage| match stage {
        DurableAdmissionCallbackStageV1::WorkspaceCurrent => {
            B::SignerAdmissionCallbackWorkspaceCurrent
        }
        DurableAdmissionCallbackStageV1::Custody => B::SignerAdmissionCallbackCustody,
        DurableAdmissionCallbackStageV1::RequestValidation => {
            B::SignerAdmissionCallbackRequestValidation
        }
    });
    diagnostic::emit_admission_measurement(failure.measurement());
    let (error, callback_error) = failure.into_errors();
    diagnostic::emit(boundary, diagnostic::authority_error(&error));
    if let Some(boundary) = io_boundary {
        diagnostic::emit(boundary, diagnostic::authority_error(&error));
    }
    if let Some(error) = callback_error {
        diagnostic::emit(
            B::SignerAdmissionCallCallbackError,
            diagnostic::signer_error(&error),
        );
        if let Some(boundary) = callback_boundary {
            diagnostic::emit(boundary, diagnostic::signer_error(&error));
        }
    }
}
fn durable_admission_dispatch_error(
    mut failure: DurableAdmissionDispatchFailureV1,
) -> &'static str {
    // Emit before this failed worker command drops its original entry. The Host
    // awaits witness drainage before reading Done, so receipt consumption cannot
    // be required for optional evidence. No telemetry changes the original error.
    diagnostic::emit_signer_admission(&failure);
    if let Some(call) = failure.take_call_failure() {
        durable_admission_call_error(call);
    }
    use DurableAdmissionDispatchStageV1 as S;
    let boundary = match failure.stage() {
        S::FixtureState => B::SignerAdmissionDispatchFixtureState,
        S::ReviewCorrelation => B::SignerAdmissionDispatchReviewCorrelation,
        S::NativeApproval => B::SignerAdmissionDispatchNativeApproval,
        S::IntentRetention => B::SignerAdmissionDispatchIntentRetention,
        S::SubmitCustody => B::SignerAdmissionDispatchSubmitCustody,
        S::SubmitIntent => B::SignerAdmissionDispatchSubmitIntent,
        S::SubmitInterval => B::SignerAdmissionDispatchSubmitInterval,
        S::SubmitWorkspace => B::SignerAdmissionDispatchSubmitWorkspace,
        S::AuthorityCall => B::SignerAdmissionDispatchAuthorityCall,
        S::WorkerCompletion => B::SignerAdmissionDispatchWorkerCompletion,
        S::CommittedCorrelation => B::SignerAdmissionDispatchCommittedCorrelation,
    };
    if let Some(error) = failure.original_error() {
        diagnostic::emit(boundary, diagnostic::signer_error(error));
    }
    signer_error(
        failure.into_error(),
        "native retained-intent durable admission",
    )
}
pub(super) const AGREEMENT_ID: &str = "synthetic-born-joined-agreement-v3";
pub(super) const OBLIGATION_ID: &str = "synthetic-born-joined-obligation-v3";
pub(super) const PARTICIPANT_IDS: [&str; 3] = [
    "synthetic-anchor",
    "synthetic-owner-one",
    "synthetic-owner-two",
];
pub(super) const RECIPIENT_ID: &str = "synthetic-payment-recipient-v3";
pub(super) const RECIPIENT_PROVENANCE: &str =
    "Synthetic temporary public receiver; no ownership or receipt claim.";
#[derive(Clone)]
pub(super) struct PublicJoinedBornV1 {
    pub index: usize,
    pub account_id: String,
    pub birth_digest: String,
    pub full_viewing_key_digest: String,
    pub network_profile_id: String,
    pub participant_id: String,
    pub privacy_domain: String,
    pub public_receive_address: String,
    pub recipient_scope_digest: String,
}
pub(super) struct JoinedSignerPeerV1 {
    pub endpoint: PathBuf,
    pub provider: InstalledSignerProvider,
    pub deadline: Instant,
}
pub(super) enum JoinedSignerCommandV1 {
    CaptureAndArmStartedV2(usize, Instant),
    ProbeDurableResultGrantV2(usize, wholepact_signer::native_ui::synthetic_born_joined_qualification::DurableResultGrantProbeV2, Option<std::os::unix::net::UnixStream>, Arc<AtomicBool>),
    BeginReopenedFinancialContinuationV2(usize, String, EphemeralWitnessOriginV1, Arc<wholepact_signer::native_ui::synthetic_born_joined_qualification::PreservedDurablePairV2>),
    PreserveReopenedFinancialContinuationV2(usize),
    OpenDurableResultInPairV2(usize, DeliveryReopenV2, Arc<wholepact_signer::native_ui::synthetic_born_joined_qualification::PreservedDurablePairV2>),
    OpenDurableResultV2(usize, DeliveryReopenV2),
    ReadDurableResultPeerV2(usize),
    ServeDurableResultV2(usize, Arc<AtomicBool>),
    PreserveDurableResultV2(usize),
    BeginFinancialContinuation(usize, String),
    PollFinancialContinuation(usize),
    ApproveFinancialContinuation(usize),
    SendFinancialContinuation(usize),
    ReadFinancialContinuationRequest(usize),
    ReadFinancialActivationRequest(usize),
    ReadFinancialResultPeer(usize),
    ServeFinancialResult(usize, Arc<AtomicBool>),
    PreserveFinancialContinuation(usize),
    DropUnselectedAnchor(usize),
    OpenDelivery(usize, wholepact_core::ProposalInput),
    DeliveryPeer(usize),
    ReadDeliverySourceMetadata(usize),
    PollDeliveryPair(usize),
    AcceptDelivery(usize),
    ConfigureDeliveryWitness(usize),
    PollDeliveryRedisclosure(usize, DurableConstructionRedisclosureRequestV1, Arc<AtomicBool>),
    PrepareClosedDelivery(usize, DurableReviewDeliveryRequestV1, wholepact_protocol::durable_proposal_v1::FixedProposalIdentityV1, String, u64, wholepact_authority::durable_delivery_scope_v2::DurableDeliveryPlanV2, Vec<wholepact_authority::durable_delivery_scope_v2::DurableDeliveryMaterialScopeRefV2>, Arc<AtomicBool>),
    PollClosedDeliveryImport(usize, wholepact_protocol::durable_proposal_v1::FixedProposalIdentityV1, Arc<AtomicBool>),
    PollClosedDeliveryAdmission(usize),
    ApproveClosedDelivery(usize),
    AwaitClosedDeliveryResponse(usize, Arc<AtomicBool>),
    AwaitClosedDeliveryAudit(usize, Arc<AtomicBool>),
    ReopenClosedDeliveryAudit(usize),
    PollDeliveryImport(usize, DurableReviewDeliveryRequestV1, wholepact_protocol::durable_proposal_v1::FixedProposalIdentityV1),
    PollDeliveryAdmission(usize, wholepact_signer::authority_bridge::durable_delivery_admission_ipc_v2::DurableDeliveryAdmissionRequestV2),
    ApproveDelivery(usize),
    AwaitDeliveryResponse(usize),
    AwaitDeliveryAudit(usize),
    ServeDeliveryData(usize, Arc<AtomicBool>),
    AuditDeliveryDenials(usize),
    PreserveDelivery(usize),
    CloseDeliveryReader(usize),
    ServeOriginalEvidence(Arc<AtomicBool>),
    ExportBirth(usize),
    Acknowledge(usize),
    OpenSingleIntent(usize, HostManualEnrollmentIntent),
    PollAndExportSingle(usize),
    OpenSinglePublication(usize, HostManualEnrollmentRequest),
    PollSinglePublication(usize),
    CloseSinglePublication(usize),
    OpenRosterIntent(usize, HostManualRosterEnrollmentIntentV2),
    PollAndExportRoster(usize),
    OpenRosterPublication(usize, HostManualRosterPublicationRequestV2),
    PollRosterPublication(usize),
    CloseRosterPublication(usize),
    OpenDurable(usize, wholepact_core::ProposalInput),
    OpenDurableObserved(usize, wholepact_core::ProposalInput),
    PollDurablePair(usize),
    ConfigureDurableWitness(usize),
    PrepareDurableAdmission(usize),
    ApproveDurableAdmission(usize),
    ObserveCommittedDurableAdmission(usize, wholepact_authority::OwnerControlRequest),
    ReconcileDurableWriter(usize),
    AcquireDurableWriterExpectingReplyLoss(usize),
    RetryDurableWriterAfterReplyLoss(usize),
    ConfigureDurableWallet(usize, String),
    AcceptDurable(usize),
    ArmInitial(usize, PreconstructionRequest),
    ArmCapture(usize, DurableConstructionCaptureRequestV1),
    ArmRedisclosure(usize, DurableConstructionRedisclosureRequestV1),
    PollImport(
        usize,
        DurableReviewDeliveryRequestV1,
        wholepact_protocol::durable_proposal_v1::FixedProposalIdentityV1,
    ),
    PollFinancialImport(
        usize,
        DurableReviewDeliveryRequestV1,
        wholepact_protocol::durable_proposal_v1::FixedProposalIdentityV1,
    ),
    SignDurableFixed(
        usize,
        wholepact_protocol::durable_proposal_v1::FixedProposalIdentityV1,
    ),
    ServeDurableResult(usize, Arc<AtomicBool>),
    PollDisclosure(usize),
    CaptureCommitted(usize),
    CloseDurable(usize),
}
pub(super) use wholepact_signer::native_ui::synthetic_born_joined_qualification::DurableDeliveryReopenSelectorV2 as DeliveryReopenV2;
pub(super) enum JoinedSignerReplyV1 {
    FinancialStartedCustodyV2 { index: usize, custody: wholepact_signer::native_ui::synthetic_born_joined_qualification::StartedFinancialCustodyV2 },
    DurableResultGrantProbeV2 { index: usize, outcome: wholepact_signer::native_ui::synthetic_born_joined_qualification::DurableResultGrantProbeOutcomeV2 },
    DurableResultPeerV2 { index: usize, peer: JoinedSignerPeerV1, request: wholepact_signer::authority_bridge::financial_continuation_v1::DurableFinancialResultRequestV2 },
    DeliverySourceMetadata { index: usize, json: String },
    FinancialPhase { index: usize, phase: wholepact_signer::native_ui::synthetic_born_joined_qualification::FinancialQualificationPhaseV1 },
    FinancialRequest { index: usize, request: Option<OwnerControlRequest> },
    FinancialResultPeer { index: usize, peer: JoinedSignerPeerV1, request: wholepact_signer::authority_bridge::financial_continuation_v1::FinancialResultRequestV1 },
    ClosedDeliveryStatus { index: usize, status: wholepact_signer::authority_bridge::durable_delivery_admission_ipc_v3::DurableDeliveryAdmissionStatusV3 },
    DeliveryStatus { index: usize, status: wholepact_signer::authority_bridge::durable_delivery_admission_ipc_v2::DurableDeliveryAdmissionStatusV2 },
    DeliveryPreserved { index: usize, original: DeliveryReopenV2 },
    BirthExport {
        index: usize,
        account_id: String,
        birth_digest: String,
        exported_file: PathBuf,
    },
    Acknowledged(PublicJoinedBornV1),
    Peer(JoinedSignerPeerV1),
    SingleExport {
        index: usize,
        signed_extension_file: PathBuf,
        enrollment_request: HostManualEnrollmentRequest,
    },
    RosterExport {
        index: usize,
        signed_extension_file: PathBuf,
        original_policy_file: PathBuf,
        enrollment_request: HostManualRosterEnrollmentRequestV2,
    },
    DurablePeer {
        index: usize,
        peer: JoinedSignerPeerV1,
        scope: PairScope,
        entry_digest: String,
    },
    Records {
        index: usize,
        records: DurableNativeRecordsV1,
    },
    CaptureCommitted {
        index: usize,
        reference: String,
    },
    DurableAuthorization {
        index: usize,
        history: HistoryRequest,
        commit: AuthorizationCommit,
    },
    DurableAdmissionRequest {
        index: usize,
        request: OwnerControlRequest,
    },
    DurableAcquireReplyLost {
        index: usize,
        observation: DurableAcquireReplyLossV1,
    },
    DurableAcquireRetried {
        index: usize,
        receipt: wholepact_authority::WriterSessionReceipt,
    },
    Done {
        index: usize,
    },
}
struct OriginalPublic {
    account_id: String,
    full_viewing_key_digest: String,
    network_profile_id: String,
    recipient_scope_digest: String,
}
enum State {
    DurableResultReopenV2(DeliveryReopenV2),
    DurableResultV2(Box<wholepact_signer::native_ui::synthetic_born_joined_qualification::EphemeralDurableResultNativeV2>),
    Pending(Box<EphemeralPendingBornV1>),
    ExportedBirth(Box<EphemeralExportedBirthV1>),
    Acknowledged(Box<EphemeralAcknowledgedBornV1>),
    SingleIntent(Box<EphemeralFirstAnchorIntentV1>),
    SinglePublication(Box<EphemeralFirstAnchorPublicationV1>, bool),
    RosterIntent(Box<EphemeralOriginalRosterIntentV1>),
    RosterPublication(Box<EphemeralRosterPublicationV1>, bool),
    Durable(Box<EphemeralDurableNativeV1>),
    Delivery(Box<EphemeralDurableDeliveryNativeV2>),
    ClosedDelivery(Box<EphemeralClosedDeliveryNativeV3>),
    FinancialContinuation(Box<wholepact_signer::native_ui::synthetic_born_joined_qualification::EphemeralFinancialContinuationNativeV1>, FinancialProgressReporter),
    ClosedReopen(DeliveryReopenV2, wholepact_signer::authority_bridge::durable_review_ipc_v3::RecipientIntentV3),
    PreservedDelivery,
}
enum OriginalWitnessOriginsV1 {
    ConstructorOnly(EphemeralWitnessOriginV1),
    Distinct([EphemeralWitnessOriginV1; 3]),
}
pub(super) struct JoinedSignerWorkerV1 {
    commands: Option<Sender<JoinedSignerCommandV1>>,
    replies: Receiver<Result<JoinedSignerReplyV1>>,
    cancelled: Arc<AtomicBool>,
    join: Option<JoinHandle<()>>,
}
impl JoinedSignerWorkerV1 {
    pub fn spawn(
        origin: EphemeralWitnessOriginV1,
        payment_receiver: String,
        expiry_ms: u64,
    ) -> Result<Self> {
        let (commands, incoming) = mpsc::channel();
        let (outgoing, replies) = mpsc::channel();
        let (started, startup) = mpsc::sync_channel(1);
        let cancelled = Arc::new(AtomicBool::new(false));
        let flag = cancelled.clone();
        let join = thread::Builder::new()
            .name("synthetic-durable-native".into())
            .stack_size(8 * 1024 * 1024)
            .spawn(move || {
                let (mut states, public) = match create_originals(
                    OriginalWitnessOriginsV1::ConstructorOnly(origin),
                    &payment_receiver,
                    expiry_ms,
                ) {
                    Ok(v) => v,
                    Err(e) => {
                        let _ = started.send(Err(e));
                        return;
                    }
                };
                if started.send(Ok(())).is_err() {
                    return;
                }
                while !flag.load(Ordering::Acquire) {
                    let command = match incoming.recv_timeout(Duration::from_millis(20)) {
                        Ok(v) => v,
                        Err(mpsc::RecvTimeoutError::Timeout) => continue,
                        Err(_) => break,
                    };
                    let reply = execute(command, &mut states, Some(&public), &flag);
                    let failed = reply.is_err();
                    if outgoing.send(reply).is_err() || failed {
                        break;
                    }
                }
                drop(states);
            })
            .map_err(|_| "durable worker thread")?;
        let mut worker = Self {
            commands: Some(commands),
            replies,
            cancelled,
            join: Some(join),
        };
        match startup.recv() {
            Ok(Ok(())) => Ok(worker),
            Ok(Err(e)) => {
                worker.stop_and_join()?;
                Err(e)
            }
            Err(_) => {
                worker.stop_and_join()?;
                Err("durable startup disconnected")
            }
        }
    }
    /// Fresh native production entries over the same preserved originals.
    /// This reader neither recreates birth nor accepts another manifest.
    pub fn reopen_delivery(originals: [DeliveryReopenV2; 2]) -> Result<Self> {
        let (commands, incoming) = mpsc::channel();
        let (outgoing, replies) = mpsc::channel();
        let (started, startup) = mpsc::sync_channel(1);
        let cancelled = Arc::new(AtomicBool::new(false));
        let flag = cancelled.clone();
        let join = thread::Builder::new()
            .name("synthetic-delivery-original-reader".into())
            .stack_size(8 * 1024 * 1024)
            .spawn(move || {
                let opened = (|| -> Result<[Option<State>; 3]> {
                    let mut states: [Option<State>; 3] = std::array::from_fn(|_| None);
                    for (slot, original) in originals.into_iter().enumerate() {
                        let entry =
                            EphemeralDurableDeliveryNativeV2::reopen_original_selector(original)
                                .map_err(durable_entry_error)?;
                        states[slot + 1] = Some(State::Delivery(Box::new(entry)));
                    }
                    Ok(states)
                })();
                let mut states = match opened {
                    Ok(states) => states,
                    Err(error) => {
                        let _ = started.send(Err(error));
                        return;
                    }
                };
                if started.send(Ok(())).is_err() {
                    return;
                }
                while !flag.load(Ordering::Acquire) {
                    let command = match incoming.recv_timeout(Duration::from_millis(20)) {
                        Ok(command) => command,
                        Err(mpsc::RecvTimeoutError::Timeout) => continue,
                        Err(_) => break,
                    };
                    let reply = execute(command, &mut states, None, &flag);
                    let failed = reply.is_err();
                    if outgoing.send(reply).is_err() || failed {
                        break;
                    }
                }
                drop(states);
            })
            .map_err(|_| "delivery reader thread")?;
        let mut worker = Self {
            commands: Some(commands),
            replies,
            cancelled,
            join: Some(join),
        };
        match startup.recv() {
            Ok(Ok(())) => Ok(worker),
            Ok(Err(error)) => {
                worker.stop_and_join()?;
                Err(error)
            }
            Err(_) => {
                worker.stop_and_join()?;
                Err("delivery reader startup disconnected")
            }
        }
    }
    /// Stores only inert original selectors. Each actual read entry is opened
    /// later, after that owner's authenticated history listener is established.
    pub fn reopen_closed_delivery(
        originals: [DeliveryReopenV2; 2],
        intents: [wholepact_signer::authority_bridge::durable_review_ipc_v3::RecipientIntentV3; 2],
    ) -> Result<Self> {
        let (commands, incoming) = mpsc::channel();
        let (outgoing, replies) = mpsc::channel();
        let cancelled = Arc::new(AtomicBool::new(false));
        let flag = cancelled.clone();
        let join = thread::Builder::new()
            .name("synthetic-closed-delivery-reader".into())
            .stack_size(8 * 1024 * 1024)
            .spawn(move || {
                let mut states: [Option<State>; 3] = std::array::from_fn(|_| None);
                for (slot, (original, intent)) in originals.into_iter().zip(intents).enumerate() {
                    states[slot + 1] = Some(State::ClosedReopen(original, intent));
                }
                while !flag.load(Ordering::Acquire) {
                    let command = match incoming.recv_timeout(Duration::from_millis(20)) {
                        Ok(command) => command,
                        Err(mpsc::RecvTimeoutError::Timeout) => continue,
                        Err(_) => break,
                    };
                    let reply = execute(command, &mut states, None, &flag);
                    let failed = reply.is_err();
                    if outgoing.send(reply).is_err() || failed {
                        break;
                    }
                }
                drop(states);
            })
            .map_err(|_| "closed reader thread")?;
        Ok(Self {
            commands: Some(commands),
            replies,
            cancelled,
            join: Some(join),
        })
    }
    /// Closed qualification routing over exact preserved original selectors.
    /// Version20 is completed data; version2 is genuinely unexported pre-export
    /// source. A selected opener failure never falls back to another profile.
    /// This thread worker alone does not prove an OS-process restart.
    pub fn reopen_result_v2(originals: [Option<DeliveryReopenV2>; 2]) -> Result<Self> {
        // The enclosing PartialReady control must validate both selectors
        // under its actually owned root before this qualification constructor.
        // Exactly the last drained Arc<TempDir> owner marked preservation;
        // earlier false flags are retained verbatim, not upgraded to authority.
        let [Some(a), Some(b)] = &originals else { return Err("durable V2 complete container selectors"); };
        if originals.iter().flatten().any(|s| !matches!(s.version, 2 | 20)
                || !s.root.is_absolute() || s.root.as_os_str().len() > 4096
                || !s.root.components().all(|c| matches!(c, std::path::Component::RootDir | std::path::Component::Normal(_))))
            || originals.iter().flatten().filter(|s| s.original_directory_preserved).count() != 1
            || a.account_id == b.account_id || a.root == b.root
        { return Err("durable V2 exact mixed selectors"); }
        let a_root = std::fs::canonicalize(&a.root).map_err(|_| "durable V2 original root")?;
        let b_root = std::fs::canonicalize(&b.root).map_err(|_| "durable V2 original root")?;
        let parent = a_root.parent().ok_or("durable V2 original container")?;
        if a_root != a.root || b_root != b.root || parent.parent().is_none()
            || b_root.parent() != Some(parent)
        { return Err("durable V2 shared original container"); }
        let (commands, incoming) = mpsc::channel();
        let (outgoing, replies) = mpsc::channel();
        let (started, startup) = mpsc::sync_channel(1);
        let cancelled = Arc::new(AtomicBool::new(false));
        let flag = cancelled.clone();
        let join = thread::Builder::new()
            .name("synthetic-durable-result-v2-reader".into())
            .stack_size(8 * 1024 * 1024)
            .spawn(move || {
                let opened = (|| -> Result<[Option<State>; 3]> {
                    let mut states: [Option<State>; 3] = std::array::from_fn(|_| None);
                    for (slot, original) in originals.into_iter().enumerate() {
                        states[slot + 1] = match original {
                            None => None,
                            Some(original) => Some(match original.version {
                                20 => State::DurableResultReopenV2(original),
                                2 => State::Delivery(Box::new(
                                    EphemeralDurableDeliveryNativeV2::reopen_original_selector(original)
                                        .map_err(durable_entry_error)?)),
                                _ => return Err("durable V2 unsupported source version"),
                            }),
                        };
                    }
                    Ok(states)
                })();
                let mut states = match opened {
                    Ok(states) => states,
                    Err(error) => { let _ = started.send(Err(error)); return; }
                };
                if started.send(Ok(())).is_err() { return; }
                while !flag.load(Ordering::Acquire) {
                    let command = match incoming.recv_timeout(Duration::from_millis(20)) {
                        Ok(command) => command,
                        Err(mpsc::RecvTimeoutError::Timeout) => continue,
                        Err(_) => break,
                    };
                    let reply = execute(command, &mut states, None, &flag);
                    let failed = reply.is_err();
                    if outgoing.send(reply).is_err() || failed { break; }
                }
                drop(states);
            }).map_err(|_| "durable V2 reader thread")?;
        let mut worker = Self { commands: Some(commands), replies, cancelled, join: Some(join) };
        match startup.recv() {
            Ok(Ok(())) => Ok(worker),
            Ok(Err(error)) => { worker.stop_and_join()?; Err(error) },
            Err(_) => { worker.stop_and_join()?; Err("durable V2 reader startup disconnected") },
        }
    }
    pub fn send(&self, command: JoinedSignerCommandV1) -> Result<()> {
        if self.cancelled.load(Ordering::Acquire) {
            return Err("durable worker cancelled");
        }
        self.commands
            .as_ref()
            .ok_or("durable worker closed")?
            .send(command)
            .map_err(|_| "durable command disconnected")
    }
    pub fn receive(&self) -> Result<JoinedSignerReplyV1> {
        self.replies
            .recv()
            .map_err(|_| "durable reply disconnected")?
    }
    pub fn shutdown(mut self) -> Result<()> {
        self.stop_and_join()
    }
    fn stop_and_join(&mut self) -> Result<()> {
        self.cancelled.store(true, Ordering::Release);
        self.commands.take();
        if let Some(join) = self.join.take() {
            join.join().map_err(|_| "durable worker panicked")?;
        }
        Ok(())
    }
}
impl Drop for JoinedSignerWorkerV1 {
    fn drop(&mut self) {
        let _ = self.stop_and_join();
    }
}

fn create_originals(
    origins: OriginalWitnessOriginsV1,
    payment_receiver: &str,
    expiry_ms: u64,
) -> Result<([Option<State>; 3], [OriginalPublic; 3])> {
    let mut public: [Option<OriginalPublic>; 3] = std::array::from_fn(|_| None);
    let pins = match &origins {
        OriginalWitnessOriginsV1::ConstructorOnly(origin) => {
            std::array::from_fn(|_| origin.clone())
        }
        OriginalWitnessOriginsV1::Distinct(origins) => (*origins).clone(),
    };
    diagnostic::emit(B::SignerCreate, Outcome::Begin);
    let mut setup = |index: usize, identity: &wholepact_signer::native_ui::synthetic_born_joined_qualification::PublicBornIdentityV1| {
        let pins = pins.get(index).ok_or(wholepact_signer::Error::InvalidData)?;
        let participant = PARTICIPANT_IDS
            .get(index)
            .ok_or(wholepact_signer::Error::InvalidData)?;
        let stable = BornConstructionRecipientPolicyV2 {
            version: 2,
            account_id: identity.account_id.clone(),
            network_profile_id: identity.network_profile_id.clone(),
            agreement_id: AGREEMENT_ID.into(),
            obligation_id: OBLIGATION_ID.into(),
            participant_id: (*participant).into(),
            recipients: vec![BornRecipientLimitV2 {
                recipient_id: RECIPIENT_ID.into(),
                address: payment_receiver.into(),
                memo: None,
                instruction_provenance: RECIPIENT_PROVENANCE.into(),
                maximum_amount_zatoshis: 300_000,
            }],
            charges: vec![],
            original_limits: BornOriginalLimitsV2 {
                aggregate_budget_zatoshis: 1_000_000,
                per_operation_limit_zatoshis: 400_000,
                maximum_fee_share_zatoshis: 10_000,
                maximum_transaction_fee_zatoshis: 20_000,
                maximum_permit_lifetime_ms: 120_000,
                policy_expires_at_ms: expiry_ms,
            },
            own_return_rule: BornOwnReturnRuleV2::AuthenticatedSameAccount,
        };
        let recipient_scope_digest = stable
            .digest()
            .map_err(|_| wholepact_signer::Error::InvalidData)?;
        // Original policy requires a nonempty inert requested-enrollment
        // allowlist. This public test label is NOT an enrollment record or a
        // predecessor: the actual manual extension derives its distinct ref.
        let mut requested = Sha256::new();
        requested.update(b"wholepact:synthetic-joined-requested-enrollment:v1\0");
        requested.update(identity.account_id.as_bytes());
        let policy = AccountPolicy {
            account_use_genesis: None,
            witness_id: pins.witness_id.clone(),
            account_id: identity.account_id.clone(),
            network_profile_id: identity.network_profile_id.clone(),
            owner_certificate_digest: pins.owner_certificate_digest.clone(),
            initial_writer_certificate_digest: pins.writer_certificate_digest.clone(),
            initial_writer_epoch: 1,
            enrollment_refs: vec![hex::encode(requested.finalize())],
            agreement_ids: vec![AGREEMENT_ID.into()],
            recipient_scope_digests: vec![recipient_scope_digest.clone()],
            aggregate_budget_zatoshis: stable.original_limits.aggregate_budget_zatoshis,
            per_operation_limit_zatoshis: stable.original_limits.per_operation_limit_zatoshis,
            maximum_fee_share_zatoshis: stable.original_limits.maximum_fee_share_zatoshis,
            maximum_transaction_fee_zatoshis: stable
                .original_limits
                .maximum_transaction_fee_zatoshis,
            maximum_permit_lifetime_ms: stable.original_limits.maximum_permit_lifetime_ms,
            policy_expires_at_ms: expiry_ms,
        };
        policy
            .validate()
            .map_err(|_| wholepact_signer::Error::InvalidData)?;
        public[index] = Some(OriginalPublic {
            account_id: identity.account_id.clone(),
            full_viewing_key_digest: identity.full_viewing_key_digest.clone(),
            network_profile_id: identity.network_profile_id.clone(),
            recipient_scope_digest,
        });
        Ok(OriginalBirthSetupV1 {
            policy,
            stable_recipient_policy_json: serde_json::to_string(&stable)
                .map_err(|_| wholepact_signer::Error::InvalidData)?,
        })
    };
    let accounts = match origins {
        OriginalWitnessOriginsV1::ConstructorOnly(origin) => {
            EphemeralPendingBornV1::create_three(origin, &mut setup)
        }
        OriginalWitnessOriginsV1::Distinct(origins) => {
            EphemeralPendingBornV1::create_three_with_original_witnesses(origins, &mut setup)
        }
    }
    .map_err(|error| {
        diagnostic::emit(B::SignerCreate, diagnostic::signer_error(&error));
        "actual three pending birth controllers"
    })?;
    diagnostic::emit(B::SignerCreate, Outcome::Complete);
    let [anchor, one, two] = public;
    let public = [
        anchor.ok_or("anchor public policy metadata")?,
        one.ok_or("first participant public policy metadata")?,
        two.ok_or("second participant public policy metadata")?,
    ];
    for (account, metadata) in accounts.iter().zip(&public) {
        if account.account_id() != metadata.account_id {
            return Err("actual pending identity differs from reviewed policy");
        }
    }
    Ok((
        accounts.map(|account| Some(State::Pending(Box::new(account)))),
        public,
    ))
}

fn poll_until(
    deadline: Instant,
    cancelled: &AtomicBool,
    mut poll: impl FnMut() -> wholepact_signer::Result<bool>,
    stage: &'static str,
) -> Result<()> {
    loop {
        if cancelled.load(Ordering::Acquire) {
            diagnostic::emit(B::SignerPollCancelled, Outcome::Begin);
            return Err("signer worker cancelled while polling");
        }
        if Instant::now() >= deadline {
            diagnostic::emit(B::SignerPollDeadline, Outcome::Begin);
            return Err("actual signer entry deadline elapsed");
        }
        let result = poll();
        if let Err(error) = &result {
            diagnostic::emit(B::SignerPollTerminal, diagnostic::signer_error(error));
        }
        if result.map_err(|error| signer_error(error, stage))? {
            return Ok(());
        }
        thread::sleep(Duration::from_millis(2));
    }
}

// Host completion bounds only the response-serving wait. It neither proves a
// native outcome nor grants authority; an early failed Host call terminates
// through the unchanged fixture error/drop-drain path instead of timing out.
fn closed_delivery_host_complete(
    terminal: bool,
    host_complete: &AtomicBool,
) -> wholepact_signer::Result<bool> {
    if !host_complete.load(Ordering::Acquire) {
        return Ok(false);
    }
    if !terminal {
        return Err(wholepact_signer::Error::Uncertain);
    }
    Ok(true)
}

// Data-only terminal failure observation precedes the same pending-stop checks.
// A queued success is not returned by take_failure and still traverses the
// borrowed wait's original live and full successful-exit gates.
fn delivery_import_poll_step<S, E>(
    state: &mut S,
    mut take_failure: impl FnMut(&mut S) -> Option<E>,
    live: impl FnOnce() -> std::result::Result<(), E>,
    poll: impl FnOnce(&mut S) -> std::result::Result<bool, E>,
) -> std::result::Result<bool, E> {
    if let Some(error) = take_failure(state) {
        return Err(error);
    }
    live()?;
    let result = poll(state);
    if let Some(error) = take_failure(state) {
        return Err(error);
    }
    result
}

enum DeliveryImportPollError {
    Stop(&'static str),
    Signer(wholepact_signer::Error),
}

fn command_index(command: &JoinedSignerCommandV1) -> usize {
    use JoinedSignerCommandV1 as C;
    match command {
        C::ServeOriginalEvidence(_) => 0,
        C::CaptureAndArmStartedV2(i, _)
        | C::ProbeDurableResultGrantV2(i, _, _, _)
        | C::BeginReopenedFinancialContinuationV2(i, _, _, _)
        | C::PreserveReopenedFinancialContinuationV2(i)
        | C::OpenDurableResultInPairV2(i, _, _)
        | C::OpenDurableResultV2(i, _)
        | C::ReadDurableResultPeerV2(i)
        | C::ServeDurableResultV2(i, _)
        | C::PreserveDurableResultV2(i)
        | C::BeginFinancialContinuation(i, _)
        | C::PollFinancialContinuation(i)
        | C::ApproveFinancialContinuation(i)
        | C::SendFinancialContinuation(i)
        | C::ReadFinancialContinuationRequest(i)
        | C::ReadFinancialActivationRequest(i)
        | C::ReadFinancialResultPeer(i)
        | C::ServeFinancialResult(i, _)
        | C::PreserveFinancialContinuation(i)
        | C::DropUnselectedAnchor(i)
        | C::OpenDelivery(i, _)
        | C::ReadDeliverySourceMetadata(i)
        | C::DeliveryPeer(i)
        | C::PollDeliveryPair(i)
        | C::AcceptDelivery(i)
        | C::ConfigureDeliveryWitness(i)
        | C::PollDeliveryRedisclosure(i, _, _)
        | C::PrepareClosedDelivery(i, _, _, _, _, _, _, _)
        | C::PollClosedDeliveryImport(i, _, _)
        | C::PollClosedDeliveryAdmission(i)
        | C::ApproveClosedDelivery(i)
        | C::AwaitClosedDeliveryResponse(i, _)
        | C::AwaitClosedDeliveryAudit(i, _)
        | C::ReopenClosedDeliveryAudit(i)
        | C::PollDeliveryImport(i, _, _)
        | C::PollDeliveryAdmission(i, _)
        | C::ApproveDelivery(i)
        | C::AwaitDeliveryResponse(i)
        | C::AwaitDeliveryAudit(i)
        | C::ServeDeliveryData(i, _)
        | C::AuditDeliveryDenials(i)
        | C::PreserveDelivery(i)
        | C::CloseDeliveryReader(i) => *i,
        C::ExportBirth(i)
        | C::Acknowledge(i)
        | C::OpenSingleIntent(i, _)
        | C::PollAndExportSingle(i)
        | C::OpenSinglePublication(i, _)
        | C::PollSinglePublication(i)
        | C::CloseSinglePublication(i)
        | C::OpenRosterIntent(i, _)
        | C::PollAndExportRoster(i)
        | C::OpenRosterPublication(i, _)
        | C::PollRosterPublication(i)
        | C::CloseRosterPublication(i)
        | C::OpenDurable(i, _)
        | C::OpenDurableObserved(i, _)
        | C::PollDurablePair(i)
        | C::ConfigureDurableWitness(i)
        | C::PrepareDurableAdmission(i)
        | C::ApproveDurableAdmission(i)
        | C::ObserveCommittedDurableAdmission(i, _)
        | C::ReconcileDurableWriter(i)
        | C::AcquireDurableWriterExpectingReplyLoss(i)
        | C::RetryDurableWriterAfterReplyLoss(i)
        | C::ConfigureDurableWallet(i, _)
        | C::AcceptDurable(i)
        | C::ArmInitial(i, _)
        | C::ArmCapture(i, _)
        | C::ArmRedisclosure(i, _)
        | C::PollImport(i, _, _)
        | C::PollFinancialImport(i, _, _)
        | C::SignDurableFixed(i, _)
        | C::ServeDurableResult(i, _)
        | C::PollDisclosure(i)
        | C::CaptureCommitted(i)
        | C::CloseDurable(i) => *i,
    }
}

fn delivery_failure_error(
    failure: wholepact_signer::native_ui::synthetic_born_joined_qualification::DurableDeliveryFailureV2,
) -> wholepact_signer::Error {
    use wholepact_signer::native_ui::synthetic_born_joined_qualification::DurableDeliveryStageV2 as S;
    let (_attempt, stage, error, import, transport) = failure.into_parts();
    let boundary = match stage {
        S::Import => B::DeliveryArtifactImport,
        S::OriginalEvidence => B::DeliveryCredentialRegistration,
        S::History | S::Audit => B::DeliveryHistoricalRead,
        _ => B::DeliveryNativeAdmission,
    };
    if let Some(import) = import {
        use wholepact_signer::authority_bridge::BridgeError as E;
        let outcome = match import {
            E::Binding => Outcome::BridgeBinding,
            E::Conflict => Outcome::BridgeConflict,
            E::Missing => Outcome::BridgeMissing,
            E::Uncertain => Outcome::BridgeUncertain,
            E::Limit => Outcome::BridgeLimit,
            E::Permission => Outcome::BridgePermission,
            E::RecoveryRequired => Outcome::BridgeRecoveryRequired,
            E::CompleteOriginRecoveryUnavailable => {
                Outcome::BridgeCompleteOriginRecoveryUnavailable
            }
            E::Verification => Outcome::BridgeVerification,
            E::SignerOriginUnavailable => Outcome::BridgeSignerOriginUnavailable,
            E::Journal(_) => Outcome::BridgeJournal,
            E::Authority(_) => Outcome::BridgeAuthority,
            E::Wallet(_) => Outcome::BridgeWallet,
            E::Ipc => Outcome::BridgeIpc,
        };
        diagnostic::emit_delivery_observation(boundary, outcome);
    }
    if let Some(transport) = transport {
        let admission = matches!(stage, S::OwnerSend);
        if admission {
            diagnostic::emit_admission_measurement(transport.measurement());
        } else {
            diagnostic::emit_history_measurement(transport.measurement());
        }
        diagnostic::emit_delivery_observation(
            checked_authority_boundary(transport.stage(), admission).unwrap_or(boundary),
            diagnostic::authority_error(&transport.error()),
        );
    }
    diagnostic::emit_delivery_observation(boundary, diagnostic::signer_error(&error));
    error
}

fn delivery_peer(
    index: usize,
    entry: &EphemeralDurableDeliveryNativeV2,
) -> Result<JoinedSignerReplyV1> {
    Ok(JoinedSignerReplyV1::DurablePeer {
        index,
        peer: JoinedSignerPeerV1 {
            endpoint: entry
                .endpoint()
                .map_err(|error| signer_error(error, "delivery endpoint"))?,
            provider: entry
                .provider()
                .map_err(|error| signer_error(error, "delivery provider"))?,
            deadline: entry
                .deadline()
                .map_err(|error| signer_error(error, "delivery deadline"))?,
        },
        scope: entry.scope().clone(),
        entry_digest: entry.native_entry_digest().into(),
    })
}

// Keep the fresh roster opener off the large unrelated-command frame.
// This dispatch observes only the closed command tag, never authority or slots.
#[inline(never)]
fn execute(
    command: JoinedSignerCommandV1,
    states: &mut [Option<State>; 3],
    public: Option<&[OriginalPublic; 3]>,
    cancelled: &AtomicBool,
) -> Result<JoinedSignerReplyV1> {
    if matches!(&command, JoinedSignerCommandV1::OpenRosterIntent(..)) {
        execute_open_roster_intent(command, states)
    } else if matches!(&command, JoinedSignerCommandV1::OpenRosterPublication(..)) {
        execute_open_roster_publication(command, states)
    } else {
        execute_other(command, states, public, cancelled)
    }
}

#[inline(never)]
fn execute_open_roster_intent(
    command: JoinedSignerCommandV1,
    states: &mut [Option<State>; 3],
) -> Result<JoinedSignerReplyV1> {
    use JoinedSignerCommandV1 as C;
    use JoinedSignerReplyV1 as R;
    let index = command_index(&command);
    let slot = states.get_mut(index).ok_or("durable account index")?;
    let state = slot.take().ok_or("durable retained state missing")?;
    let (next, reply) = match (command, state) {
        (C::OpenRosterIntent(_, intent), State::Acknowledged(account)) if index > 0 => {
            let entry = (*account)
                .open_initial_intent(intent)
                .map_err(|error| signer_error(error, "native roster intent entry"))?;
            let reply = R::Peer(JoinedSignerPeerV1 {
                endpoint: entry
                    .endpoint()
                    .map_err(|error| signer_error(error, "roster intent endpoint"))?,
                provider: entry
                    .provider()
                    .map_err(|error| signer_error(error, "roster intent provider"))?,
                deadline: entry
                    .deadline()
                    .map_err(|error| signer_error(error, "roster intent deadline"))?,
            });
            (State::RosterIntent(Box::new(entry)), reply)
        }
        _ => return Err("durable finite native transition mismatch"),
    };
    *slot = Some(next);
    Ok(reply)
}

#[inline(never)]
fn execute_open_roster_publication(
    command: JoinedSignerCommandV1,
    states: &mut [Option<State>; 3],
) -> Result<JoinedSignerReplyV1> {
    use JoinedSignerCommandV1 as C;
    use JoinedSignerReplyV1 as R;
    let index = command_index(&command);
    let slot = states.get_mut(index).ok_or("durable account index")?;
    let state = slot.take().ok_or("durable retained state missing")?;
    let (next, reply) = match (command, state) {
        (C::OpenRosterPublication(_, request), State::Acknowledged(account)) if index > 0 => {
            let entry = (*account)
                .open_initial_publication(request)
                .map_err(|error| signer_error(error, "native initial roster publication entry"))?;
            let reply = R::Peer(JoinedSignerPeerV1 {
                endpoint: entry
                    .endpoint()
                    .map_err(|error| signer_error(error, "roster publication endpoint"))?,
                provider: entry
                    .provider()
                    .map_err(|error| signer_error(error, "roster publication provider"))?,
                deadline: entry
                    .deadline()
                    .map_err(|error| signer_error(error, "roster publication deadline"))?,
            });
            (State::RosterPublication(Box::new(entry), false), reply)
        }
        _ => return Err("durable finite native transition mismatch"),
    };
    *slot = Some(next);
    Ok(reply)
}

#[inline(never)]
fn execute_other(
    command: JoinedSignerCommandV1,
    states: &mut [Option<State>; 3],
    public: Option<&[OriginalPublic; 3]>,
    cancelled: &AtomicBool,
) -> Result<JoinedSignerReplyV1> {
    use JoinedSignerCommandV1 as C;
    use JoinedSignerReplyV1 as R;
    if let C::ServeOriginalEvidence(stop) = &command {
        // Both exact old paired originals stay responsive during the consuming
        // registration's repeated metadata-only source checks. This loop does
        // not accept a review, manifest or payment request.
        let deadline = states[1..]
            .iter()
            .try_fold(None, |deadline: Option<Instant>, state| {
                let Some(State::Durable(entry)) = state else {
                    return Err("original evidence state");
                };
                let current = entry
                    .deadline()
                    .map_err(|error| signer_error(error, "original evidence deadline"))?;
                Ok(Some(deadline.map_or(current, |old| old.min(current))))
            })?
            .ok_or("original evidence owners missing")?;
        while !stop.load(Ordering::Acquire) {
            if cancelled.load(Ordering::Acquire) || Instant::now() >= deadline {
                return Err("original evidence cancelled or expired");
            }
            for state in &mut states[1..] {
                let Some(State::Durable(entry)) = state else {
                    return Err("original evidence state changed");
                };
                entry
                    .poll_data_only()
                    .map_err(|error| signer_error(error, "original evidence native poll"))?;
            }
            thread::sleep(Duration::from_millis(5));
        }
        return Ok(R::Done { index: 0 });
    }
    let index = command_index(&command);
    let slot = states.get_mut(index).ok_or("durable account index")?;
    let state = slot.take().ok_or("durable retained state missing")?;
    let (next, reply) = match (command, state) {
        (C::DropUnselectedAnchor(_), State::Acknowledged(account)) if index == 0 => {
            drop(account);
            (State::PreservedDelivery, R::Done { index })
        }
        (C::OpenDelivery(_, proposal), State::Acknowledged(account)) if index > 0 => {
            let entry = (*account)
                .open_fresh_durable_delivery_v2(proposal, 1_000_000)
                .map_err(durable_entry_error)?;
            let reply = delivery_peer(index, &entry)?;
            (State::Delivery(Box::new(entry)), reply)
        }
        (C::ReadDeliverySourceMetadata(_), State::Delivery(entry)) => {
            let json = entry.coordinated_pre_v3_metadata().map_err(|error| signer_error(error, "original source metadata"))?;
            (State::Delivery(entry), R::DeliverySourceMetadata { index, json })
        }
        (C::DeliveryPeer(_), State::Delivery(entry)) => {
            let reply = delivery_peer(index, &entry)?;
            (State::Delivery(entry), reply)
        }
        (C::PollDeliveryPair(_), State::Delivery(mut entry)) => {
            poll_until(
                entry
                    .deadline()
                    .map_err(|error| signer_error(error, "delivery pair deadline"))?,
                cancelled,
                || entry.poll_exact_pairing(),
                "exact delivery native pairing",
            )?;
            (State::Delivery(entry), R::Done { index })
        }
        (C::AcceptDelivery(_), State::Delivery(mut entry)) => {
            let records = entry
                .accept_exact_manifest()
                .map_err(|error| signer_error(error, "exact delivery accepted manifest"))?;
            (State::Delivery(entry), R::Records { index, records })
        }
        (C::ConfigureDeliveryWitness(_), State::Delivery(mut entry)) => {
            entry
                .configure_original_witness()
                .map_err(|error| signer_error(error, "delivery original owner configuration"))?;
            (State::Delivery(entry), R::Done { index })
        }
        (C::PollDeliveryRedisclosure(_, request, stop), State::Delivery(mut entry)) => {
            let deadline = entry
                .deadline()
                .map_err(|error| signer_error(error, "delivery redisclosure deadline"))?;
            poll_until(
                deadline,
                cancelled,
                || {
                    entry.poll_exact_redisclosure(&request).map_err(|error| {
                        diagnostic::emit_delivery_observation(
                            B::DeliveryRedisclosure,
                            diagnostic::signer_error(&error),
                        );
                        error
                    })
                },
                "exact original current-recipient native redisclosure",
            )?;
            // A genuine native approval starts the maintained asynchronous
            // retain-before-bytes worker. Continue servicing only this entry
            // until the actual paired client receives its bounded response.
            while !stop.load(Ordering::Acquire) {
                if cancelled.load(Ordering::Acquire) || Instant::now() >= deadline {
                    return Err("delivery redisclosure cancelled or expired");
                }
                entry.poll_data_only().map_err(|error| {
                    signer_error(error, "delivery redisclosure native response")
                })?;
                if let Some(failure) = entry.take_failure() {
                    return Err(signer_error(
                        delivery_failure_error(failure),
                        "delivery redisclosure worker refused",
                    ));
                }
                thread::sleep(Duration::from_millis(5));
            }
            (State::Delivery(entry), R::Done { index })
        }
        (
            C::PrepareClosedDelivery(
                _,
                request,
                fixed,
                digest,
                bytes,
                plan,
                materials,
                host_complete,
            ),
            State::Delivery(mut entry),
        ) => {
            // This is an outer fixture wait only. No action/read permission is
            // created by this budget; the production decision issues READ120.
            // Ready alone is not wire completion: keep the actual runtime
            // responsive until the matching Host preparation call has returned.
            poll_until(
                Instant::now() + Duration::from_secs(120),
                cancelled,
                || {
                    let ready = entry
                        .poll_closed_receive_review_v3(
                            &request, &fixed, &digest, bytes, &plan, &materials,
                        )
                        .map_err(|error| {
                            closed_delivery_error(error, B::DeliveryRecipientPrepare)
                        })?;
                    closed_delivery_host_complete(ready, &host_complete)
                        .map_err(|error| closed_delivery_error(error, B::DeliveryRecipientPrepare))
                },
                "actual source-bound receive-and-view review",
            )?;
            let entry = entry
                .into_closed_delivery_v3()
                .map_err(|error| signer_error(error, "closed source custody handoff"))?;
            (State::ClosedDelivery(Box::new(entry)), R::Done { index })
        }
        (
            C::PollClosedDeliveryImport(_, fixed, host_complete),
            State::ClosedDelivery(mut entry),
        ) => {
            poll_until(
                entry
                    .deadline()
                    .map_err(|error| signer_error(error, "closed import deadline"))?,
                cancelled,
                || {
                    let verified = entry
                        .poll_verified_import(&fixed)
                        .map_err(|error| closed_delivery_error(error, B::DeliveryArtifactImport))?;
                    closed_delivery_host_complete(verified, &host_complete)
                        .map_err(|error| closed_delivery_error(error, B::DeliveryArtifactImport))
                },
                "actual closed exact-byte import verification",
            )?;
            (State::ClosedDelivery(entry), R::Done { index })
        }
        (C::PollClosedDeliveryAdmission(_), State::ClosedDelivery(mut entry)) => {
            let mut actual = None;
            poll_until(
                entry
                    .deadline()
                    .map_err(|error| signer_error(error, "conditional admission read deadline"))?,
                cancelled,
                || {
                    actual = entry.poll_admission_review().map_err(|error| {
                        closed_delivery_error(error, B::DeliveryNativeAdmission)
                    })?;
                    Ok(actual.is_some())
                },
                "actual exact conditional admission review",
            )?;
            (
                State::ClosedDelivery(entry),
                R::DurableAdmissionRequest {
                    index,
                    request: actual.ok_or("closed exact review missing")?,
                },
            )
        }
        (C::ApproveClosedDelivery(_), State::ClosedDelivery(mut entry)) => {
            entry.approve_conditional_admission().map_err(|error| {
                signer_error(
                    closed_delivery_error(error, B::DeliveryNativeAdmission),
                    "conditional exact admission decision",
                )
            })?;
            (State::ClosedDelivery(entry), R::Done { index })
        }
        (C::AwaitClosedDeliveryResponse(_, host_complete), State::ClosedDelivery(mut entry)) => {
            poll_until(
                entry
                    .deadline()
                    .map_err(|error| signer_error(error, "closed admission deadline"))?,
                cancelled,
                || {
                    let retained = entry.admission_pending().map_err(|error| {
                        closed_delivery_error(error, B::DeliveryNativeAdmission)
                    })?;
                    closed_delivery_host_complete(retained, &host_complete)
                        .map_err(|error| closed_delivery_error(error, B::DeliveryNativeAdmission))
                },
                "actual retained admission or unknown intermediate",
            )?;
            let status = entry
                .status()
                .map_err(|error| signer_error(error, "closed retained status"))?;
            (
                State::ClosedDelivery(entry),
                R::ClosedDeliveryStatus { index, status },
            )
        }
        (C::ReopenClosedDeliveryAudit(_), State::ClosedReopen(original, intent)) => {
            let mut entry = EphemeralClosedDeliveryNativeV3::open_history_existing(
                original, intent,
            )
            .map_err(|error| {
                signer_error(
                    closed_delivery_error(error, B::DeliveryOriginalReopen),
                    "actual original V3 read-only reopen",
                )
            })?;
            poll_until(
                Instant::now() + Duration::from_secs(120),
                cancelled,
                || {
                    entry
                        .poll_history_audit()
                        .map_err(|error| closed_delivery_error(error, B::DeliveryHistoricalRead))
                },
                "actual original fresh read-only history",
            )?;
            let status = entry
                .status()
                .map_err(|error| signer_error(error, "reopened V3 history result"))?;
            status
                .verified_audit()
                .map_err(|_| "reopened V3 history not verified")?;
            // The initial genuine history review opens the read-only entry.
            // Its local result is not a substitute for the Host's fresh
            // recipient handshake and verified response on this endpoint.
            let peer = JoinedSignerPeerV1 {
                endpoint: entry
                    .endpoint()
                    .map_err(|error| signer_error(error, "reopened V3 history endpoint"))?,
                provider: entry
                    .provider()
                    .map_err(|error| signer_error(error, "reopened V3 history provider"))?,
                deadline: entry
                    .deadline()
                    .map_err(|error| signer_error(error, "reopened V3 history deadline"))?,
            };
            (State::ClosedDelivery(Box::new(entry)), R::Peer(peer))
        }
        (C::AwaitClosedDeliveryAudit(_, host_complete), State::ClosedDelivery(mut entry)) => {
            // Fresh history review is a separate closed purpose. No prior
            // transport/read grant is used as authority for this wait.
            // A reopened entry already has a local Complete phase. Continue
            // processing the exact pending HistoryRecipient review and wire
            // requests until the matching Host history client has returned.
            poll_until(
                Instant::now() + Duration::from_secs(120),
                cancelled,
                || {
                    let complete = entry
                        .poll_history_audit()
                        .map_err(|error| closed_delivery_error(error, B::DeliveryHistoricalRead))?;
                    closed_delivery_host_complete(complete, &host_complete)
                        .map_err(|error| closed_delivery_error(error, B::DeliveryHistoricalRead))
                },
                "fresh exact read-only complete history audit",
            )?;
            let status = entry
                .status()
                .map_err(|error| signer_error(error, "closed verified status"))?;
            status
                .verified_audit()
                .map_err(|_| "closed audit not verified")?;
            (
                State::ClosedDelivery(entry),
                R::ClosedDeliveryStatus { index, status },
            )
        }
        (C::CaptureAndArmStartedV2(_, outer_deadline), State::FinancialContinuation(mut entry, reporter)) => {
            let custody = entry.capture_and_arm_started_v2(outer_deadline).map_err(|e| signer_error(e, "actual pre-Sign Started custody and one-shot arm"))?;
            (State::FinancialContinuation(entry, reporter), R::FinancialStartedCustodyV2 { index, custody })
        }
        (C::ProbeDurableResultGrantV2(_, probe, other_stream, stop), State::DurableResultV2(mut entry)) => {
            use wholepact_signer::native_ui::synthetic_born_joined_qualification::{DurableResultGrantProbeV2 as Probe, DurableResultQualificationPhaseV2 as Phase};
            let deadline = entry.deadline().map_err(|e| signer_error(e, "grant probe original bound"))?;
            let read_probe = matches!(probe, Probe::WrongRequestRead | Probe::WrongRecipientRead | Probe::RevokedRead);
            loop {
                if cancelled.load(Ordering::Acquire) || stop.load(Ordering::Acquire) || Instant::now() >= deadline {
                    return Err("grant probe cancelled or original bound expired");
                }
                let phase = entry.poll().map_err(|e| signer_error(e, "grant probe actual native poll"))?;
                if phase == if read_probe { Phase::ReadReview } else { Phase::ReturnReview } { break; }
                match phase {
                    Phase::ReadReview if !read_probe => entry.approve_current_review().map_err(|e| signer_error(e, "grant probe genuine preview Read"))?,
                    Phase::AwaitingRequest | Phase::Preparing => (),
                    _ => return Err("grant probe unexpected native phase"),
                }
                thread::sleep(Duration::from_millis(5));
            }
            let outcome = entry.probe_grant(probe, other_stream, &stop).map_err(|e| signer_error(e, "actual native grant denial probe"))?;
            // Already failed closed; preserve only after the actual source drain.
            let _original = entry.close_preserving_originals().map_err(|e| signer_error(e, "grant probe source drain"))?;
            (State::PreservedDelivery, R::DurableResultGrantProbeV2 { index, outcome })
        }
        (C::BeginReopenedFinancialContinuationV2(_, wallet, origin, pair), State::ClosedDelivery(entry)) => {
            let entry = entry.into_financial_continuation_reopened_v2(wallet, origin, pair)
                .map_err(|e| signer_error(e, "cold V2 actual financial entry"))?;
            let reporter = FinancialProgressReporter::start(index, &entry);
            (State::FinancialContinuation(Box::new(entry), reporter), R::Done { index })
        }
        (C::PreserveReopenedFinancialContinuationV2(_), State::FinancialContinuation(entry, reporter)) => {
            drop(reporter);
            let original = entry.close_preserving_reopened_v2().map_err(|e| signer_error(e, "cold V2 actual financial drain"))?;
            (State::PreservedDelivery, R::DeliveryPreserved { index, original })
        }
        (C::OpenDurableResultInPairV2(_, selector, pair), State::PreservedDelivery) => {
            let entry = wholepact_signer::native_ui::synthetic_born_joined_qualification::EphemeralDurableResultNativeV2::open_existing_in_pair(selector, pair)
                .map_err(|e| signer_error(e, "paired V2 actual result reopen"))?;
            (State::DurableResultV2(Box::new(entry)), R::Done { index })
        }
        (C::OpenDurableResultV2(_, selector), State::DurableResultReopenV2(expected)) => {
            if serde_json::to_vec(&selector).map_err(|_| "durable V2 selector encode")?
                != serde_json::to_vec(&expected).map_err(|_| "durable V2 retained selector encode")?
            { return Err("durable V2 selector replacement"); }
            let entry = wholepact_signer::native_ui::synthetic_born_joined_qualification::EphemeralDurableResultNativeV2::open_existing(selector)
                .map_err(|e| signer_error(e, "durable V2 actual cold native reopen"))?;
            (State::DurableResultV2(Box::new(entry)), R::Done { index })
        }
        (C::OpenDurableResultV2(_, selector), State::PreservedDelivery) => {
            let entry = wholepact_signer::native_ui::synthetic_born_joined_qualification::EphemeralDurableResultNativeV2::open_existing(selector)
                .map_err(|e| signer_error(e, "durable V2 actual native reopen"))?;
            (State::DurableResultV2(Box::new(entry)), R::Done { index })
        }
        (C::ReadDurableResultPeerV2(_), State::DurableResultV2(entry)) => {
            let peer = JoinedSignerPeerV1 {
                provider: entry.provider().map_err(|e| signer_error(e, "durable V2 actual provider"))?,
                endpoint: entry.endpoint().map_err(|e| signer_error(e, "durable V2 protected endpoint"))?,
                deadline: entry.deadline().map_err(|e| signer_error(e, "durable V2 original ceiling"))?,
            };
            let request = entry.result_request().map_err(|e| signer_error(e, "durable V2 audited selector"))?;
            (State::DurableResultV2(entry), R::DurableResultPeerV2 { index, peer, request })
        }
        (C::ServeDurableResultV2(_, stop), State::DurableResultV2(mut entry)) => {
            use wholepact_signer::native_ui::synthetic_born_joined_qualification::DurableResultQualificationPhaseV2 as P;
            let deadline = entry.deadline().map_err(|e| signer_error(e, "durable V2 original ceiling"))?;
            let mut stopping_since = None;
            loop {
                if cancelled.load(Ordering::Acquire) || Instant::now() >= deadline {
                    return Err("durable V2 cancelled or original ceiling expired");
                }
                let phase = entry.poll().map_err(|e| signer_error(e, "durable V2 actual native poll"))?;
                if stop.load(Ordering::Acquire) {
                    if phase == P::Complete { break; }
                    let since = stopping_since.get_or_insert_with(Instant::now);
                    if !matches!(phase, P::Preparing | P::Returning) || since.elapsed() >= Duration::from_secs(2) {
                        return Err("durable V2 stopped without exact completion");
                    }
                    thread::sleep(Duration::from_millis(5));
                    continue;
                }
                match phase {
                    P::ReadReview | P::ReturnReview => entry.approve_current_review().map_err(|e| signer_error(e, "durable V2 actual read/return click"))?,
                    P::AwaitingRequest | P::Preparing | P::Returning => (),
                    P::Complete => break,
                    _ => return Err("durable V2 unexpected native purpose"),
                }
                thread::sleep(Duration::from_millis(5));
            }
            (State::DurableResultV2(entry), R::Done { index })
        }
        (C::PreserveDurableResultV2(_), State::DurableResultV2(entry)) => {
            let original = entry.close_preserving_originals().map_err(|e| signer_error(e, "durable V2 actual source drain"))?;
            (State::PreservedDelivery, R::DeliveryPreserved { index, original })
        }
        (C::BeginFinancialContinuation(_, wallet), State::ClosedDelivery(entry)) => {
            let entry = entry.into_financial_continuation_v1(wallet).map_err(|e| {
                financial_signer_error(
                    e,
                    "exact original financial source entry",
                    crate::host::financial_diagnostics_v1::FinancialStageV1::WorkerSourceOpen,
                    None,
                )
            })?;
            let reporter = FinancialProgressReporter::start(index, &entry);
            (
                State::FinancialContinuation(Box::new(entry), reporter),
                R::Done { index },
            )
        }
        (C::PollFinancialContinuation(_), State::FinancialContinuation(mut entry, reporter)) => {
            let phase = entry.poll().map_err(|e| {
                financial_signer_error(
                    e,
                    "financial native phase",
                    crate::host::financial_diagnostics_v1::FinancialStageV1::WorkerPhaseWait,
                    entry.last_failure_v1(),
                )
            })?;
            (
                State::FinancialContinuation(entry, reporter),
                R::FinancialPhase { index, phase },
            )
        }
        (C::ApproveFinancialContinuation(_), State::FinancialContinuation(mut entry, reporter)) => {
            entry.approve_current_review().map_err(|e| {
                financial_signer_error(
                    e,
                    "financial exact final native review",
                    crate::host::financial_diagnostics_v1::FinancialStageV1::WorkerReview,
                    entry.last_failure_v1(),
                )
            })?;
            (
                State::FinancialContinuation(entry, reporter),
                R::Done { index },
            )
        }
        (C::SendFinancialContinuation(_), State::FinancialContinuation(mut entry, reporter)) => {
            entry.send_pending_continuation().map_err(|e| {
                financial_signer_error(
                    e,
                    "financial exact retained admission send",
                    crate::host::financial_diagnostics_v1::FinancialStageV1::WorkerCommand,
                    entry.last_failure_v1(),
                )
            })?;
            (
                State::FinancialContinuation(entry, reporter),
                R::Done { index },
            )
        }
        (C::ReadFinancialContinuationRequest(_), State::FinancialContinuation(entry, reporter)) => {
            let request = entry.pending_continuation_request().map_err(|e| {
                financial_signer_error(
                    e,
                    "financial exact pending request",
                    crate::host::financial_diagnostics_v1::FinancialStageV1::WorkerRequest,
                    entry.last_failure_v1(),
                )
            })?;
            (
                State::FinancialContinuation(entry, reporter),
                R::FinancialRequest { index, request },
            )
        }
        (C::ReadFinancialActivationRequest(_), State::FinancialContinuation(entry, reporter)) => {
            let request = entry.pending_activation_request().map_err(|e| {
                financial_signer_error(
                    e,
                    "financial exact activation request",
                    crate::host::financial_diagnostics_v1::FinancialStageV1::WorkerRequest,
                    entry.last_failure_v1(),
                )
            })?;
            (
                State::FinancialContinuation(entry, reporter),
                R::FinancialRequest { index, request },
            )
        }
        (C::ReadFinancialResultPeer(_), State::FinancialContinuation(entry, reporter)) => {
            let peer = JoinedSignerPeerV1 {
                provider: entry.provider().map_err(|e| {
                    financial_signer_error(
                        e,
                        "financial installed provider",
                        crate::host::financial_diagnostics_v1::FinancialStageV1::WorkerRequest,
                        entry.last_failure_v1(),
                    )
                })?,
                endpoint: entry.endpoint().map_err(|e| {
                    financial_signer_error(
                        e,
                        "financial protected endpoint",
                        crate::host::financial_diagnostics_v1::FinancialStageV1::WorkerRequest,
                        entry.last_failure_v1(),
                    )
                })?,
                deadline: entry.deadline().map_err(|e| {
                    financial_signer_error(
                        e,
                        "financial original deadline",
                        crate::host::financial_diagnostics_v1::FinancialStageV1::WorkerRequest,
                        entry.last_failure_v1(),
                    )
                })?,
            };
            let request = entry.result_request().map_err(|e| {
                financial_signer_error(
                    e,
                    "financial exact result request",
                    crate::host::financial_diagnostics_v1::FinancialStageV1::WorkerRequest,
                    entry.last_failure_v1(),
                )
            })?;
            (
                State::FinancialContinuation(entry, reporter),
                R::FinancialResultPeer {
                    index,
                    peer,
                    request,
                },
            )
        }
        (C::ServeFinancialResult(_, stop), State::FinancialContinuation(mut entry, reporter)) => {
            use wholepact_signer::native_ui::synthetic_born_joined_qualification::FinancialQualificationPhaseV1 as P;
            let deadline = entry.deadline().map_err(|e| {
                financial_signer_error(
                    e,
                    "financial result original deadline",
                    crate::host::financial_diagnostics_v1::FinancialStageV1::WorkerReturn,
                    entry.last_failure_v1(),
                )
            })?;
            let mut stopping_since = None;
            loop {
                if Instant::now() >= deadline {
                    return Err("financial result original deadline expired");
                }
                let phase = entry.poll().map_err(|e| {
                    financial_signer_error(
                        e,
                        "financial actual return native poll",
                        crate::host::financial_diagnostics_v1::FinancialStageV1::WorkerReturn,
                        entry.last_failure_v1(),
                    )
                })?;
                if stop.load(Ordering::Acquire) {
                    if phase == P::Complete {
                        break;
                    }
                    let since = stopping_since.get_or_insert_with(Instant::now);
                    if phase != P::Working || since.elapsed() >= Duration::from_secs(2) {
                        return Err("financial return stopped without exact completion");
                    }
                    thread::sleep(Duration::from_millis(5));
                    continue;
                }
                match phase {
                    P::ReadReview | P::ReturnReview => entry
                        .approve_current_review()
                        .map_err(|e| financial_signer_error(e, "financial actual read/return primary", crate::host::financial_diagnostics_v1::FinancialStageV1::WorkerReview, entry.last_failure_v1()))?,
                    P::AwaitingReturn | P::Working => (),
                    P::Complete => break,
                    _ => return Err("financial return unexpected native purpose"),
                }
                thread::sleep(Duration::from_millis(5));
            }
            (
                State::FinancialContinuation(entry, reporter),
                R::Done { index },
            )
        }
        (C::PreserveFinancialContinuation(_), State::FinancialContinuation(entry, reporter)) => {
            drop(reporter);
            let original = entry.close_preserving_originals().map_err(|e| {
                financial_signer_error(
                    e,
                    "financial original native drain",
                    crate::host::financial_diagnostics_v1::FinancialStageV1::WorkerDrain,
                    None,
                )
            })?;
            (
                State::PreservedDelivery,
                R::DeliveryPreserved { index, original },
            )
        }
        (C::AuditDeliveryDenials(_), State::ClosedDelivery(mut entry)) => {
            entry
                .require_financial_routes_denied()
                .map_err(|error| signer_error(error, "closed financial routes denied"))?;
            (State::ClosedDelivery(entry), R::Done { index })
        }
        (C::CloseDeliveryReader(_), State::ClosedDelivery(entry)) => {
            entry
                .close_existing_entry()
                .map_err(|error| signer_error(error, "closed historical reader drain"))?;
            (State::PreservedDelivery, R::Done { index })
        }
        (C::PreserveDelivery(_), State::ClosedDelivery(entry)) => {
            let original = entry
                .close_preserving_originals()
                .map_err(|error| signer_error(error, "closed original preserve"))?;
            (
                State::PreservedDelivery,
                R::DeliveryPreserved { index, original },
            )
        }
        (C::PollDeliveryImport(_, request, identity), State::Delivery(mut entry)) => {
            if let Some(failure) = entry.drain_import_failure_before_wait(&request) {
                return Err(signer_error(
                    delivery_failure_error(failure),
                    "exact delivery native source import",
                ));
            }
            {
                let mut wait = entry
                    .begin_import_wait(&request, &identity)
                    .map_err(|error| signer_error(error, "delivery import wait entry"))?;
                let deadline = wait.deadline();
                loop {
                    let complete = delivery_import_poll_step(
                        &mut wait,
                        |wait| {
                            wait.take_failure().map(|failure| {
                                DeliveryImportPollError::Signer(delivery_failure_error(failure))
                            })
                        },
                        || {
                            if cancelled.load(Ordering::Acquire) {
                                diagnostic::emit(B::SignerPollCancelled, Outcome::Begin);
                                return Err(DeliveryImportPollError::Stop(
                                    "signer worker cancelled while polling",
                                ));
                            }
                            if Instant::now() >= deadline {
                                diagnostic::emit(B::SignerPollDeadline, Outcome::Begin);
                                return Err(DeliveryImportPollError::Stop(
                                    "actual signer entry deadline elapsed",
                                ));
                            }
                            Ok(())
                        },
                        |wait| wait.poll().map_err(DeliveryImportPollError::Signer),
                    )
                    .map_err(|error| match error {
                        DeliveryImportPollError::Stop(message) => message,
                        DeliveryImportPollError::Signer(error) => {
                            signer_error(error, "exact delivery native source import")
                        }
                    })?;
                    if complete {
                        break;
                    }
                    thread::sleep(Duration::from_millis(2));
                }
            }
            (State::Delivery(entry), R::Done { index })
        }
        (C::PollDeliveryAdmission(_, request), State::Delivery(mut entry)) => {
            let mut actual = None;
            poll_until(
                entry
                    .deadline()
                    .map_err(|error| signer_error(error, "delivery review deadline"))?,
                cancelled,
                || {
                    let result = entry.poll_admission_review(&request);
                    if let Some(failure) = entry.take_failure() {
                        return Err(delivery_failure_error(failure));
                    }
                    actual = result?;
                    Ok(actual.is_some())
                },
                "exact prospective delivery admission review",
            )?;
            (
                State::Delivery(entry),
                R::DurableAdmissionRequest {
                    index,
                    request: actual.ok_or("delivery native review missing")?,
                },
            )
        }
        (C::ApproveDelivery(_), State::Delivery(mut entry)) => {
            entry
                .approve_admission()
                .map_err(|error| signer_error(error, "delivery genuine native approval"))?;
            (State::Delivery(entry), R::Done { index })
        }
        (C::AwaitDeliveryResponse(_), State::Delivery(mut entry)) => {
            poll_until(
                entry
                    .deadline()
                    .map_err(|error| signer_error(error, "delivery owner-response deadline"))?,
                cancelled,
                || {
                    entry.poll_data_only()?;
                    if let Some(failure) = entry.take_failure() {
                        return Err(delivery_failure_error(failure));
                    }
                    entry.admission_response_received()
                },
                "actual unaudited owner response and retained original intent",
            )?;
            (State::Delivery(entry), R::Done { index })
        }
        (C::AwaitDeliveryAudit(_), State::Delivery(mut entry)) => {
            // This invokes the actual production read-only continuation exactly
            // once. No native admission approval or owner send is replayed.
            entry.begin_admission_history_audit().map_err(|error| {
                signer_error(error, "delivery explicit read-only audit continuation")
            })?;
            let mut status = None;
            poll_until(
                entry
                    .deadline()
                    .map_err(|error| signer_error(error, "delivery commit deadline"))?,
                cancelled,
                || {
                    entry.poll_data_only()?;
                    if let Some(failure) = entry.take_failure() {
                        return Err(delivery_failure_error(failure));
                    }
                    status = entry.admission_status()?;
                    Ok(status.is_some())
                },
                "exact delivery immutable intent and witness status",
            )?;
            (
                State::Delivery(entry),
                R::DeliveryStatus {
                    index,
                    status: status.ok_or("delivery native status missing")?,
                },
            )
        }
        (C::ServeDeliveryData(_, stop), State::Delivery(mut entry)) => {
            let deadline = entry
                .deadline()
                .map_err(|error| signer_error(error, "delivery history deadline"))?;
            while !stop.load(Ordering::Acquire) {
                if cancelled.load(Ordering::Acquire) || Instant::now() >= deadline {
                    return Err("delivery history cancelled or expired");
                }
                entry
                    .poll_data_only()
                    .map_err(|error| signer_error(error, "delivery data-only native poll"))?;
                if let Some(failure) = entry.take_failure() {
                    return Err(signer_error(
                        delivery_failure_error(failure),
                        "delivery data-only source failure",
                    ));
                }
                thread::sleep(Duration::from_millis(5));
            }
            (State::Delivery(entry), R::Done { index })
        }
        (C::AuditDeliveryDenials(_), State::Delivery(mut entry)) => {
            entry.require_financial_routes_denied().map_err(|error| {
                signer_error(error, "delivery financial routes must remain denied")
            })?;
            (State::Delivery(entry), R::Done { index })
        }
        (C::CloseDeliveryReader(_), State::Delivery(entry)) => {
            entry
                .close_existing_entry()
                .map_err(|error| signer_error(error, "delivery historical reader drain"))?;
            (State::PreservedDelivery, R::Done { index })
        }
        (C::PreserveDelivery(_), State::Delivery(entry)) => {
            let original = entry.close_preserving_originals().map_err(|error| {
                signer_error(error, "delivery native drain and preserve originals")
            })?;
            (
                State::PreservedDelivery,
                R::DeliveryPreserved { index, original },
            )
        }
        (C::ExportBirth(_), State::Pending(account)) => {
            let exported = (*account)
                .export_owner_request()
                .map_err(|error| signer_error(error, "native birth request sign and export"))?;
            let reply = R::BirthExport {
                index,
                account_id: exported.account_id().into(),
                birth_digest: exported.birth_digest().into(),
                exported_file: exported.exported_file().into(),
            };
            (State::ExportedBirth(Box::new(exported)), reply)
        }
        (C::Acknowledge(_), State::ExportedBirth(exported)) => {
            let account = (*exported).acknowledge_original().map_err(|error| {
                signer_error(error, "native original birth history and acknowledgement")
            })?;
            let metadata = &public.ok_or("original birth metadata unavailable")?[index];
            if account.account_id() != metadata.account_id {
                return Err("acknowledged identity differs from original policy");
            }
            let reply = R::Acknowledged(PublicJoinedBornV1 {
                index,
                account_id: account.account_id().into(),
                birth_digest: account.birth_digest().into(),
                full_viewing_key_digest: metadata.full_viewing_key_digest.clone(),
                network_profile_id: metadata.network_profile_id.clone(),
                participant_id: PARTICIPANT_IDS[index].into(),
                privacy_domain: account.privacy_domain().into(),
                public_receive_address: account.public_receive_address().into(),
                recipient_scope_digest: metadata.recipient_scope_digest.clone(),
            });
            (State::Acknowledged(Box::new(account)), reply)
        }
        (C::OpenSingleIntent(_, intent), State::Acknowledged(account)) if index == 0 => {
            let entry = (*account)
                .open_first_anchor_intent(intent)
                .map_err(|error| signer_error(error, "native first anchor intent entry"))?;
            let reply = R::Peer(JoinedSignerPeerV1 {
                endpoint: entry
                    .endpoint()
                    .map_err(|error| signer_error(error, "single intent endpoint"))?,
                provider: entry
                    .provider()
                    .map_err(|error| signer_error(error, "single intent provider"))?,
                deadline: entry
                    .deadline()
                    .map_err(|error| signer_error(error, "single intent deadline"))?,
            });
            (State::SingleIntent(Box::new(entry)), reply)
        }
        (C::PollAndExportSingle(_), State::SingleIntent(mut entry)) if index == 0 => {
            poll_until(
                entry
                    .deadline()
                    .map_err(|error| signer_error(error, "single intent deadline"))?,
                cancelled,
                || entry.poll_initial_intent(),
                "native single pairing and exact intent retention",
            )?;
            diagnostic::emit(B::SignerExportSingle, Outcome::Begin);
            let exported = (*entry)
                .export_original_single()
                .map_err(|error| signer_error(error, "native single owner signature and export"))?;
            let reply = R::SingleExport {
                index,
                signed_extension_file: exported.signed_extension_file().into(),
                enrollment_request: exported.enrollment_request().clone(),
            };
            (
                State::Acknowledged(Box::new(exported.close_for_witness_review())),
                reply,
            )
        }
        (C::OpenSinglePublication(_, request), State::Acknowledged(account)) if index == 0 => {
            let entry = (*account)
                .open_first_anchor_publication(request)
                .map_err(|error| signer_error(error, "native first anchor publication entry"))?;
            let reply = R::Peer(JoinedSignerPeerV1 {
                endpoint: entry
                    .endpoint()
                    .map_err(|error| signer_error(error, "single publication endpoint"))?,
                provider: entry
                    .provider()
                    .map_err(|error| signer_error(error, "single publication provider"))?,
                deadline: entry
                    .deadline()
                    .map_err(|error| signer_error(error, "single publication deadline"))?,
            });
            (State::SinglePublication(Box::new(entry), false), reply)
        }
        (C::PollSinglePublication(_), State::SinglePublication(mut entry, false)) if index == 0 => {
            poll_until(
                entry
                    .deadline()
                    .map_err(|error| signer_error(error, "single publication deadline"))?,
                cancelled,
                || entry.poll_manual_publication(),
                "native single witness admission publication and serve",
            )?;
            // Hold the source until foreground Host publication really finishes.
            (State::SinglePublication(entry, true), R::Done { index })
        }
        (C::CloseSinglePublication(_), State::SinglePublication(entry, true)) if index == 0 => (
            State::Acknowledged(Box::new((*entry).close_for_continuation())),
            R::Done { index },
        ),
        (C::OpenRosterIntent(_, intent), State::Acknowledged(account)) if index > 0 => {
            let entry = (*account)
                .open_initial_intent(intent)
                .map_err(|error| signer_error(error, "native roster intent entry"))?;
            let reply = R::Peer(JoinedSignerPeerV1 {
                endpoint: entry
                    .endpoint()
                    .map_err(|error| signer_error(error, "roster intent endpoint"))?,
                provider: entry
                    .provider()
                    .map_err(|error| signer_error(error, "roster intent provider"))?,
                deadline: entry
                    .deadline()
                    .map_err(|error| signer_error(error, "roster intent deadline"))?,
            });
            (State::RosterIntent(Box::new(entry)), reply)
        }
        (C::PollAndExportRoster(_), State::RosterIntent(mut entry)) if index > 0 => {
            poll_until(
                entry
                    .deadline()
                    .map_err(|error| signer_error(error, "roster intent deadline"))?,
                cancelled,
                || entry.poll_initial_intent(),
                "native roster pairing and exact intent retention",
            )?;
            diagnostic::emit(B::SignerExportRoster, Outcome::Begin);
            let exported = (*entry).export_original_roster().map_err(|error| {
                signer_error(error, "native roster owner signature and exact exports")
            })?;
            let reply = R::RosterExport {
                index,
                signed_extension_file: exported.signed_extension_file().into(),
                original_policy_file: exported.original_policy_file().into(),
                enrollment_request: exported.enrollment_request().clone(),
            };
            (
                State::Acknowledged(Box::new(exported.close_for_witness_review())),
                reply,
            )
        }
        (C::OpenRosterPublication(_, request), State::Acknowledged(account)) if index > 0 => {
            let entry = (*account)
                .open_initial_publication(request)
                .map_err(|error| signer_error(error, "native initial roster publication entry"))?;
            let reply = R::Peer(JoinedSignerPeerV1 {
                endpoint: entry
                    .endpoint()
                    .map_err(|error| signer_error(error, "roster publication endpoint"))?,
                provider: entry
                    .provider()
                    .map_err(|error| signer_error(error, "roster publication provider"))?,
                deadline: entry
                    .deadline()
                    .map_err(|error| signer_error(error, "roster publication deadline"))?,
            });
            (State::RosterPublication(Box::new(entry), false), reply)
        }
        (C::PollRosterPublication(_), State::RosterPublication(mut entry, false)) if index > 0 => {
            poll_until(
                entry
                    .deadline()
                    .map_err(|error| signer_error(error, "roster publication deadline"))?,
                cancelled,
                || entry.poll_manual_publication(),
                "native roster witness admission publication and serve",
            )?;
            (State::RosterPublication(entry, true), R::Done { index })
        }
        (C::CloseRosterPublication(_), State::RosterPublication(entry, true)) if index > 0 => (
            State::Acknowledged(Box::new((*entry).close_for_continuation())),
            R::Done { index },
        ),

        (C::OpenDurable(_, proposal), State::Acknowledged(account)) if index > 0 => {
            let entry = (*account)
                .open_fresh_durable(proposal, 1_000_000)
                .map_err(durable_entry_error)?;
            let reply = R::DurablePeer {
                index,
                peer: JoinedSignerPeerV1 {
                    endpoint: entry
                        .endpoint()
                        .map_err(|e| signer_error(e, "durable endpoint"))?,
                    provider: entry
                        .provider()
                        .map_err(|e| signer_error(e, "durable provider"))?,
                    deadline: entry
                        .deadline()
                        .map_err(|e| signer_error(e, "durable deadline"))?,
                },
                scope: entry.scope().clone(),
                entry_digest: entry.native_entry_digest().into(),
            };
            (State::Durable(Box::new(entry)), reply)
        }
        (C::OpenDurableObserved(_, proposal), State::Acknowledged(account)) if index > 0 => {
            // The same genuine opener and original deadline, with inert
            // lifecycle observation only for the pre-acquire qualification.
            let entry = (*account)
                .open_fresh_durable_diagnosed(proposal, 1_000_000)
                .map_err(durable_entry_error)?;
            let reply = R::DurablePeer {
                index,
                peer: JoinedSignerPeerV1 {
                    endpoint: entry
                        .endpoint()
                        .map_err(|e| signer_error(e, "durable endpoint"))?,
                    provider: entry
                        .provider()
                        .map_err(|e| signer_error(e, "durable provider"))?,
                    deadline: entry
                        .deadline()
                        .map_err(|e| signer_error(e, "durable deadline"))?,
                },
                scope: entry.scope().clone(),
                entry_digest: entry.native_entry_digest().into(),
            };
            (State::Durable(Box::new(entry)), reply)
        }
        (C::PollDurablePair(_), State::Durable(mut entry)) => {
            poll_until(
                entry
                    .deadline()
                    .map_err(|e| signer_error(e, "durable pair deadline"))?,
                cancelled,
                || entry.poll_exact_pairing(),
                "exact durable pairing",
            )?;
            (State::Durable(entry), R::Done { index })
        }
        (C::AcceptDurable(_), State::Durable(mut entry)) => {
            let records = entry
                .accept_exact_manifest()
                .map_err(|e| signer_error(e, "fresh exact enrollment and manifest"))?;
            (State::Durable(entry), R::Records { index, records })
        }
        (C::ConfigureDurableWitness(_), State::Durable(mut entry)) if index > 0 => {
            entry
                .configure_original_witness()
                .map_err(|e| signer_error(e, "exact original witness native selection"))?;
            (State::Durable(entry), R::Done { index })
        }
        (C::PrepareDurableAdmission(_), State::Durable(mut entry)) if index > 0 => {
            // Only the actual current imported source prepares this inert
            // request. Returning it is not a native approval or witness issuer.
            let request = entry
                .prepare_durable_admission()
                .map_err(durable_admission_error)?;
            (
                State::Durable(entry),
                R::DurableAdmissionRequest { index, request },
            )
        }
        (C::ApproveDurableAdmission(_), State::Durable(mut entry)) if index > 0 => {
            // The production native approval retains its immutable intent
            // before the original owner mTLS submission. Uncertainty is final
            // for this positive fixture, never a reason to invent replacement.
            entry
                .approve_durable_admission_diagnosed()
                .map_err(durable_admission_dispatch_error)?;
            (State::Durable(entry), R::Done { index })
        }
        (C::ObserveCommittedDurableAdmission(_, expected), State::Durable(mut entry))
            if index > 0 =>
        {
            // Historical recognition only. The existing runtime authenticates
            // complete history and exact immutable local intent; no approval,
            // replacement admission or writer session is created here.
            entry
                .observe_committed_durable_admission(&expected)
                .map_err(durable_admission_error)?;
            (State::Durable(entry), R::Done { index })
        }
        (C::ReconcileDurableWriter(_), State::Durable(mut entry)) if index > 0 => {
            if let Err(mut failure) = entry.reconcile_original_writer_diagnosed() {
                // Preserve the original failure, but do not seal a pending
                // worker's observations before the existing lock/cancel/drain.
                // Finalization below performs no new operation or wait.
                drop(entry);
                failure.finalize_after_drain();
                return Err(durable_flow_error(
                    failure,
                    "exact current writer native reconciliation",
                ));
            }
            (State::Durable(entry), R::Done { index })
        }
        (C::AcquireDurableWriterExpectingReplyLoss(_), State::Durable(mut entry)) if index == 1 => {
            // Expected loss is an opaque, verified nonterminal result. It must
            // never pass through durable_flow_error or emit a terminal marker.
            let observation = match entry.acquire_original_writer_expecting_reply_loss_diagnosed() {
                Ok(observation) => observation,
                Err(mut failure) => {
                    drop(entry);
                    failure.finalize_after_drain();
                    return Err(durable_flow_error(
                        failure,
                        "original writer committed Acquire reply-loss qualification",
                    ));
                }
            };
            (
                State::Durable(entry),
                R::DurableAcquireReplyLost { index, observation },
            )
        }
        (C::RetryDurableWriterAfterReplyLoss(_), State::Durable(mut entry)) if index == 1 => {
            let receipt = match entry.retry_original_writer_after_reply_loss_diagnosed() {
                Ok(receipt) => receipt,
                Err(mut failure) => {
                    drop(entry);
                    failure.finalize_after_drain();
                    return Err(durable_flow_error(
                        failure,
                        "same original writer Acquire retry after committed reply loss",
                    ));
                }
            };
            (
                State::Durable(entry),
                R::DurableAcquireRetried { index, receipt },
            )
        }
        (C::ConfigureDurableWallet(_, setup), State::Durable(mut entry)) if index > 0 => {
            entry
                .configure_durable_wallet(&setup)
                .map_err(|e| signer_error(e, "fresh exact durable viewing wallet native setup"))?;
            (State::Durable(entry), R::Done { index })
        }
        (C::ArmInitial(_, request), State::Durable(mut entry)) => {
            entry
                .expect_initial_disclosure(request)
                .map_err(|e| signer_error(e, "exact initial disclosure expectation"))?;
            (State::Durable(entry), R::Done { index })
        }
        (C::ArmCapture(_, request), State::Durable(mut entry)) => {
            entry
                .expect_durable_capture(request)
                .map_err(|e| signer_error(e, "exact durable capture expectation"))?;
            (State::Durable(entry), R::Done { index })
        }
        (C::ArmRedisclosure(_, request), State::Durable(mut entry)) => {
            entry
                .expect_redisclosure(request)
                .map_err(|e| signer_error(e, "fresh exact redisclosure expectation"))?;
            (State::Durable(entry), R::Done { index })
        }
        (C::PollImport(_, request, identity), State::Durable(mut entry)) => {
            poll_until(
                entry
                    .deadline()
                    .map_err(|e| signer_error(e, "import deadline"))?,
                cancelled,
                || entry.poll_exact_import(&request, &identity),
                "exact memory-only fixed import",
            )?;
            (State::Durable(entry), R::Done { index })
        }
        (C::PollFinancialImport(_, request, identity), State::Durable(mut entry)) if index > 0 => {
            // This distinct command cannot weaken the baseline import-only
            // helper's requirement that no current writer was reconciled.
            // Arm before the original deadline/poll. The actual import launch
            // binds this inert token; polling never resets or creates a job.
            let token = entry.arm_financial_import_diagnostics(&request, &identity);
            let result = (|| {
                let mut wait = entry
                    .begin_financial_import_wait_diagnosed(&token, &request, &identity)
                    .map_err(|e| signer_error(e, "financial import deadline"))?;
                poll_until(
                    wait.deadline(),
                    cancelled,
                    || wait.poll(),
                    "exact fixed import with separately reconciled current writer",
                )
            })();
            let observed = entry.finish_financial_import_diagnostics(
                token,
                if result.is_ok() {
                    DurableFlowResultV1::ReturnedOk
                } else {
                    DurableFlowResultV1::ReturnedErr
                },
            );
            if result.is_err() {
                if let Some(observed) = observed {
                    diagnostic::emit_durable_flow(&observed);
                }
            }
            result?;
            (State::Durable(entry), R::Done { index })
        }
        (C::SignDurableFixed(_, identity), State::Durable(mut entry)) if index > 0 => {
            // The real helper checks its original result/ledger on retry and
            // refuses any new native review, wallet job or reservation there.
            let (history, commit) = entry.sign_durable_fixed_diagnosed(&identity).map_err(|e| {
                durable_flow_error(e, "exact fixed native sign or retained-result retry")
            })?;
            (
                State::Durable(entry),
                R::DurableAuthorization {
                    index,
                    history,
                    commit,
                },
            )
        }
        (C::ServeDurableResult(_, stop), State::Durable(mut entry)) if index > 0 => {
            // Only poll the retained genuine native owner. The caller's stop
            // flag cannot approve a prompt or extend the original deadline.
            let token = entry.arm_result_service_diagnostics();
            let result = (|| {
                poll_until(
                    entry
                        .result_service_deadline_diagnosed(&token)
                        .map_err(|e| signer_error(e, "retained result service deadline"))?,
                    cancelled,
                    || {
                        if stop.load(Ordering::Acquire) {
                            return Ok(true);
                        }
                        entry.poll_result_service_diagnosed(&token)?;
                        Ok(false)
                    },
                    "nonapproving exact retained native result service",
                )
            })();
            let observed = entry.finish_result_service_diagnostics(
                token,
                if result.is_ok() {
                    DurableFlowResultV1::ReturnedOk
                } else {
                    DurableFlowResultV1::ReturnedErr
                },
            );
            if result.is_err() {
                if let Some(observed) = observed {
                    diagnostic::emit_durable_flow(&observed);
                }
            }
            result?;
            (State::Durable(entry), R::Done { index })
        }
        (C::PollDisclosure(_), State::Durable(mut entry)) => {
            {
                let mut wait = entry
                    .begin_disclosure_wait()
                    .map_err(|e| signer_error(e, "disclosure deadline"))?;
                poll_until(
                    wait.deadline(),
                    cancelled,
                    || wait.poll(),
                    "exact privacy disclosure",
                )?;
            }
            (State::Durable(entry), R::Done { index })
        }
        (C::CaptureCommitted(_), State::Durable(entry)) => {
            let reference = entry
                .exact_durable_disclosure_committed()
                .map_err(|e| signer_error(e, "native immutable outbox commit"))?;
            (
                State::Durable(entry),
                R::CaptureCommitted { index, reference },
            )
        }
        (C::CloseDurable(_), State::Durable(entry)) => {
            let account = entry
                .close_original_entry()
                .map_err(|e| signer_error(e, "native revoke and drain"))?;
            (State::Acknowledged(Box::new(account)), R::Done { index })
        }
        _ => return Err("durable finite native transition mismatch"),
    };
    *slot = Some(next);
    Ok(reply)
}

#[cfg(test)]
mod admission_diagnostic_tests {
    use super::*;

    // Layout and inert error-order checks only. They construct no native
    // authority and do not reproduce the genuine roster-intent call chain.
    #[test]
    fn durable_worker_state_layout_keeps_nominal_owners_indirect() {
        use std::mem::size_of;
        let pointer = size_of::<usize>();
        for boxed in [
            size_of::<Box<EphemeralPendingBornV1>>(),
            size_of::<Box<EphemeralExportedBirthV1>>(),
            size_of::<Box<EphemeralAcknowledgedBornV1>>(),
            size_of::<Box<EphemeralFirstAnchorIntentV1>>(),
            size_of::<Box<EphemeralFirstAnchorPublicationV1>>(),
            size_of::<Box<EphemeralOriginalRosterIntentV1>>(),
            size_of::<Box<EphemeralRosterPublicationV1>>(),
        ] { assert_eq!(boxed, pointer); }
        assert!(size_of::<State>() <= 64 * 1024);
        assert!(size_of::<[Option<State>; 3]>() <= 192 * 1024);
        // These caps alone do not prove the real caller stack budget. The
        // exact built ELF frame chain and native A/B remain separate gates.
    }

    #[test]
    fn durable_worker_execute_retains_inert_error_and_slot_order() {
        std::thread::Builder::new()
            .name("durable-worker-inert-order".into())
            .stack_size(8 * 1024 * 1024)
            .spawn(|| {
        let cancelled = AtomicBool::new(true);
        let mut states = [Some(State::PreservedDelivery), None, Some(State::PreservedDelivery)];
        assert_eq!(execute(JoinedSignerCommandV1::Acknowledge(3), &mut states, None, &cancelled).err(),
            Some("durable account index"));
        assert!(matches!(states[0].as_ref(), Some(State::PreservedDelivery)));
        assert!(states[1].is_none());
        assert!(matches!(states[2].as_ref(), Some(State::PreservedDelivery)));
        assert_eq!(execute(JoinedSignerCommandV1::Acknowledge(1), &mut states, None, &cancelled).err(),
            Some("durable retained state missing"));
        assert!(matches!(states[0].as_ref(), Some(State::PreservedDelivery)));
        assert!(states[1].is_none());
        assert!(matches!(states[2].as_ref(), Some(State::PreservedDelivery)));
        assert_eq!(execute(JoinedSignerCommandV1::Acknowledge(0), &mut states, None, &cancelled).err(),
            Some("durable finite native transition mismatch"));
        assert!(states[0].is_none());
        assert!(states[1].is_none());
        assert!(matches!(states[2].as_ref(), Some(State::PreservedDelivery)));

        // Deliberately invalid public request metadata, not native custody or
        // a healthy admission. These paths must reject before any owner call.
        let intent: HostManualRosterEnrollmentIntentV2 = serde_json::from_value(serde_json::json!({
            "version": 0,
            "account_intent": {
                "version": 0, "operation_id": "",
                "host": { "generation_id": "", "inventory_digest": "", "generation_plan_digest": "",
                    "financial_journal_origin_digest": "", "store_destination_identity": "", "profile_id": "",
                    "canonical_root": "", "destination_identity_digest": "", "inherited_identity_digest": "",
                    "scope_predecessor_digest": null },
                "scope": { "agreement_id": "", "obligation_id": "", "participant_id": "", "principal_id": "",
                    "privacy_domain": "", "recipient_scope_digests": [], "aggregate_budget_zatoshis": 0,
                    "per_operation_limit_zatoshis": 0, "maximum_fee_share_zatoshis": 0,
                    "maximum_transaction_fee_zatoshis": 0, "maximum_permit_lifetime_ms": 0, "expires_at_ms": 0 }
            },
            "roster": { "version": 0, "generation_id": "", "store_destination_identity": "", "roster_sequence": 0,
                "predecessor": { "kind": "enrollment_v1", "audit_digest": "" } }
        })).expect("inert metadata must decode without constructing authority");
        assert!(intent.validate().is_err());
        for index in 0..=3 {
            let empty = || [Some(State::PreservedDelivery), None, Some(State::PreservedDelivery)];
            let mut routed = empty();
            let mut original = empty();
            let routed_error = execute(JoinedSignerCommandV1::OpenRosterIntent(index, intent.clone()),
                &mut routed, None, &cancelled).err();
            let original_error = execute_other(JoinedSignerCommandV1::OpenRosterIntent(index, intent.clone()),
                &mut original, None, &cancelled).err();
            let expected = match index {
                3 => "durable account index",
                1 => "durable retained state missing",
                _ => "durable finite native transition mismatch",
            };
            assert_eq!(routed_error, Some(expected));
            assert_eq!(original_error, Some(expected));
            for (left, right) in routed.iter().zip(&original) {
                assert_eq!(left.is_some(), right.is_some());
                if left.is_some() { assert!(matches!(left, Some(State::PreservedDelivery))); }
                if right.is_some() { assert!(matches!(right, Some(State::PreservedDelivery))); }
            }
            assert_eq!(routed[index.min(2)].is_some(), index == 3);
        }
        // The sibling publication request is likewise inert and invalid. No
        // decoded historical claim is treated as a live account or permission.
        let publication: HostManualRosterPublicationRequestV2 = serde_json::from_value(serde_json::json!({
            "version": 0,
            "enrollment": { "terms": {
                "version": 0, "operation_id": "",
                "identity": { "account_id": "", "full_viewing_key_digest": "", "network_profile_id": "", "derivation_domain": "" },
                "birth_request_digest": "", "birth_commit_digest": "", "native_birth_digest": "",
                "original_policy_digest": "", "account_use_genesis_digest": "", "original_witness_origin_digest": "",
                "host": intent.account_intent.host.clone(), "scope": intent.account_intent.scope.clone(),
                "signer": { "enrollment_generation_id": "", "signer_target_digest": "", "original_envelope_digest": "",
                    "owner_certificate_digest": "", "writer_certificate_digest": "", "writer_epoch": 0, "native_signer_measurement": "" },
                "transport_binding_digest": "", "issued_at_ms": 0
            } },
            "roster": intent.roster.clone(), "attempt": { "kind": "initial_v2" }
        })).expect("inert publication metadata must decode without authority");
        assert!(publication.validate().is_err());
        for index in 0..=3 {
            let empty = || [Some(State::PreservedDelivery), None, Some(State::PreservedDelivery)];
            let mut routed = empty();
            let mut original = empty();
            let routed_error = execute(JoinedSignerCommandV1::OpenRosterPublication(index, publication.clone()),
                &mut routed, None, &cancelled).err();
            let original_error = execute_other(JoinedSignerCommandV1::OpenRosterPublication(index, publication.clone()),
                &mut original, None, &cancelled).err();
            let expected = match index {
                3 => "durable account index",
                1 => "durable retained state missing",
                _ => "durable finite native transition mismatch",
            };
            assert_eq!(routed_error, Some(expected));
            assert_eq!(original_error, Some(expected));
            for (left, right) in routed.iter().zip(&original) {
                assert_eq!(left.is_some(), right.is_some());
                if left.is_some() { assert!(matches!(left, Some(State::PreservedDelivery))); }
                if right.is_some() { assert!(matches!(right, Some(State::PreservedDelivery))); }
            }
            assert_eq!(routed[index.min(2)].is_some(), index == 3);
        }

            })
            .expect("inert worker-order test thread must start")
            .join()
            .expect("inert worker-order test must finish without panic");
    }

    #[test]
    fn durable_v2_command_indices_and_empty_reopen_are_data_only() {
        for index in 0..=3 {
            for command in [
                JoinedSignerCommandV1::ReadDurableResultPeerV2(index),
                JoinedSignerCommandV1::ServeDurableResultV2(index, Arc::new(AtomicBool::new(false))),
                JoinedSignerCommandV1::PreserveDurableResultV2(index),
            ] { assert_eq!(command_index(&command), index); }
        }
        // Rejects before creating a thread, source owner, provider or IPC.
        assert!(JoinedSignerWorkerV1::reopen_result_v2([None, None]).is_err());
    }

    #[test]
    fn pure_acquire_reply_loss_command_indices_preserve_existing_routes() {
        for index in 0..=3 {
            let commands = [
                JoinedSignerCommandV1::ExportBirth(index),
                JoinedSignerCommandV1::Acknowledge(index),
                JoinedSignerCommandV1::PollDurablePair(index),
                JoinedSignerCommandV1::ConfigureDurableWitness(index),
                JoinedSignerCommandV1::PrepareDurableAdmission(index),
                JoinedSignerCommandV1::ApproveDurableAdmission(index),
                JoinedSignerCommandV1::ReconcileDurableWriter(index),
                JoinedSignerCommandV1::AcquireDurableWriterExpectingReplyLoss(index),
                JoinedSignerCommandV1::RetryDurableWriterAfterReplyLoss(index),
                JoinedSignerCommandV1::AcceptDurable(index),
                JoinedSignerCommandV1::PollDisclosure(index),
                JoinedSignerCommandV1::CaptureCommitted(index),
                JoinedSignerCommandV1::CloseDurable(index),
            ];
            for command in commands {
                assert_eq!(command_index(&command), index);
            }
        }
    }

    #[test]
    fn pure_acquire_reply_loss_expected_result_is_nonterminal() {
        // Do not manufacture the opaque observation to exercise native state.
        // This source contract verifies the only success route retains Durable
        // and returns the verified observation instead of a terminal mapper.
        let source = include_str!("worker.rs")
            .split("#[cfg(test)]")
            .next()
            .unwrap();
        let first = source
            .find("C::AcquireDurableWriterExpectingReplyLoss(_)")
            .unwrap();
        let retry = source[first..]
            .find("C::RetryDurableWriterAfterReplyLoss(_)")
            .unwrap()
            + first;
        let body = &source[first..retry];
        assert!(body.contains("Ok(observation) => observation"));
        assert!(body.contains("State::Durable(entry)"));
        assert!(body.contains("R::DurableAcquireReplyLost"));
        assert!(!body.contains("diagnostic::emit("));
        assert!(!body.contains("observation.into_error()"));
        assert!(!body.contains("WriterReconcileComplete"));
    }

    #[test]
    fn pure_admission_boundary_routing_preserves_context() {
        use wholepact_authority::transport::history_diagnostics_v1::CheckedHistoryStageV1 as S;
        assert!(matches!(
            checked_authority_boundary(S::CallerDeadline, true),
            Some(B::SignerAdmissionCallCallerDeadline)
        ));
        assert!(matches!(
            checked_authority_boundary(S::ExchangeDeadline, true),
            Some(B::SignerAdmissionCallExchangeDeadline)
        ));
        assert!(matches!(
            checked_authority_boundary(S::SourceCallback, true),
            Some(B::SignerAdmissionCallSourceCallback)
        ));
        assert!(matches!(
            checked_authority_boundary(S::Bounds, true),
            Some(B::SignerAdmissionCallBounds)
        ));
        assert!(matches!(
            checked_authority_boundary(S::CallerDeadline, false),
            Some(B::SignerAdmissionHistoryCallerDeadline)
        ));
        assert!(matches!(
            checked_authority_boundary(S::ExchangeDeadline, false),
            Some(B::SignerAdmissionHistoryExchangeDeadline)
        ));
        assert!(matches!(
            checked_authority_boundary(S::SourceCallback, false),
            Some(B::SignerAdmissionHistorySourceCallback)
        ));
        assert!(matches!(
            checked_authority_boundary(S::Bounds, false),
            Some(B::SignerAdmissionHistoryBounds)
        ));
        assert!(matches!(
            checked_authority_boundary(S::AdmissionRequestWrite, true),
            Some(B::SignerAdmissionCallRequestWrite)
        ));
        assert!(matches!(
            checked_authority_boundary(S::SnapshotRequestWrite, false),
            Some(B::SignerAdmissionHistorySnapshotRequestWrite)
        ));
    }

    #[test]
    fn pure_flow_stages_are_never_reported_as_admission_or_history() {
        use wholepact_authority::transport::history_diagnostics_v1::CheckedHistoryStageV1 as S;
        for stage in [
            S::FlowRequestValidation,
            S::FlowBinding,
            S::FlowSession,
            S::FlowConnect,
            S::FlowHandshake,
            S::FlowPeerBinding,
            S::FlowRequestBuild,
            S::FlowRequestWrite,
            S::FlowResponseRead,
            S::FlowResponse,
            S::FlowSnapshotValidation,
            S::FlowReceiptValidation,
            S::FlowCommittedHeadValidation,
            S::FlowFinalValidation,
        ] {
            assert!(checked_authority_boundary(stage, false).is_none());
            assert!(checked_authority_boundary(stage, true).is_none());
        }
    }
}

#[cfg(test)]
mod delivery_import_wait_tests {
    use super::delivery_import_poll_step;
    use std::cell::RefCell;

    #[derive(Debug)]
    struct OwnedFailure(Box<u8>);

    #[test]
    fn delivery_import_worker_uses_exact_wait_without_repeated_full_audits() {
        // Source integration only, not native entry issuance or timing proof.
        let source = include_str!("worker.rs")
            .split("#[cfg(test)]\nmod delivery_import_wait_tests")
            .next()
            .unwrap();
        let start = source
            .find("(C::PollDeliveryImport(_, request, identity)")
            .unwrap();
        let end = source[start..]
            .find("(C::PollDeliveryAdmission(_, request)")
            .unwrap()
            + start;
        let body = &source[start..end];
        let drain = body
            .find("drain_import_failure_before_wait(&request)")
            .unwrap();
        let begin = body
            .find(".begin_import_wait(&request, &identity)")
            .unwrap();
        let live = body.find("cancelled.load(Ordering::Acquire)").unwrap();
        let poll = body
            .find("wait.poll().map_err(DeliveryImportPollError::Signer)")
            .unwrap();
        assert!(drain < begin && begin < live && live < poll);
        assert!(body.contains("Instant::now() >= deadline"));
        assert!(body.contains("thread::sleep(Duration::from_millis(2))"));
        assert!(!body.contains("poll_data_only"));
        assert!(!body.contains("poll_exact_import"));
        assert!(!body.contains(".take_failure()") || body.contains("wait.take_failure()"));
    }

    #[test]
    fn completed_import_error_precedes_cancellation_without_polling_or_adoption() {
        let original = OwnedFailure(Box::new(17));
        let address = &*original.0 as *const u8;
        let mut state = Some(original);
        let result = delivery_import_poll_step(
            &mut state,
            |state| state.take(),
            || panic!("completed error must be retained before stop/currentness checks"),
            |_| panic!("diagnostic drain must never poll or adopt success"),
        );
        assert_eq!(&*result.unwrap_err().0 as *const u8, address);
        assert!(state.is_none());
    }

    #[test]
    fn pending_import_stop_refusal_never_calls_poll_or_returns_success() {
        for reason in [23, 29] {
            let original = OwnedFailure(Box::new(reason));
            let address = &*original.0 as *const u8;
            let mut probes = 0;
            let result = delivery_import_poll_step(
                &mut probes,
                |probes| {
                    *probes += 1;
                    None
                },
                || Err(original),
                |_| panic!("cancelled or expired pending wait cannot poll success"),
            );
            assert_eq!(&*result.unwrap_err().0 as *const u8, address);
            assert_eq!(probes, 1);
        }
    }

    #[test]
    fn pending_import_step_preserves_pending_success_and_actual_terminal_errors() {
        for completed in [false, true] {
            let events = RefCell::new(Vec::new());
            let mut state = ();
            let result: Result<bool, OwnedFailure> = delivery_import_poll_step(
                &mut state,
                |_| {
                    events.borrow_mut().push("drain");
                    None
                },
                || {
                    events.borrow_mut().push("live");
                    Ok(())
                },
                |_| {
                    events.borrow_mut().push("poll");
                    Ok(completed)
                },
            );
            assert_eq!(result.unwrap(), completed);
            assert_eq!(*events.borrow(), ["drain", "live", "poll", "drain"]);
        }
        let original = OwnedFailure(Box::new(31));
        let address = &*original.0 as *const u8;
        let mut no_failure = ();
        let returned =
            delivery_import_poll_step(&mut no_failure, |_| None, || Ok(()), |_| Err(original))
                .unwrap_err();
        assert_eq!(&*returned.0 as *const u8, address);

        // The same actual worker Err observed by the poll is kept, rather than
        // replacing it with a later wrapper error or inventing a success.
        let original = OwnedFailure(Box::new(37));
        let address = &*original.0 as *const u8;
        let mut state = (false, Some(original));
        let returned = delivery_import_poll_step(
            &mut state,
            |state| if state.0 { state.1.take() } else { None },
            || Ok(()),
            |state| {
                state.0 = true;
                Err(OwnedFailure(Box::new(41)))
            },
        )
        .unwrap_err();
        assert_eq!(&*returned.0 as *const u8, address);
    }
}

/// Qualification-only observation thread. No authority, source access, or retry.
/// Its independently opened nonblocking stderr descriptor never changes flags
/// on the inherited PTY and never takes the process stderr formatting lock.
struct FinancialProgressReporter {
    stop: Arc<AtomicBool>,
    thread: Option<JoinHandle<()>>,
}
impl FinancialProgressReporter {
    fn start(
        index: usize,
        entry:&wholepact_signer::native_ui::synthetic_born_joined_qualification::EphemeralFinancialContinuationNativeV1,
    ) -> Self {
        let stop = Arc::new(AtomicBool::new(false));
        let mut result = Self {
            stop: stop.clone(),
            thread: None,
        };
        let Ok(owner) = u8::try_from(index) else {
            return result;
        };
        if !(1..=2).contains(&owner) {
            return result;
        }
        let Some(observer) = entry.progress_observer_v1() else {
            return result;
        };
        let Ok(deadline) = entry.deadline() else {
            return result;
        };
        let Ok(cutoff) = super::private_fixed_v2::child_original_cutoff() else {
            return result;
        };
        let deadline = deadline.min(cutoff);
        let Some(mut output) = nonblocking_financial_progress_output() else {
            return result;
        };
        result.thread = thread::Builder::new()
            .name("synthetic-financial-progress".into())
            .spawn(move || {
                use std::io::Write;
                let mut last = None;
                let mut emitted = 0u16;
                while !stop.load(Ordering::Acquire) && Instant::now() < deadline {
                    if let Some(current) = observer.snapshot() {
                        if last != Some(current) && emitted < 256 {
                            last = Some(current);
                            emitted += 1;
                            let record = super::super::financial_progress_v1::Record::Job {
                                owner,
                                job_id: current.job_id,
                                sequence: current.sequence,
                                stage: current.stage,
                            };
                            if let Ok(json) = serde_json::to_string(&record) {
                                let line = format!("\n[FINANCIAL_PROGRESS_V1 {json}]\n");
                                if line.len() <= 480 {
                                    // Exactly one nonblocking write; no retry on a
                                    // full PTY, interruption, or a partial write.
                                    if !matches!(output.write(line.as_bytes()), Ok(n) if n == line.len()) {
                                        // Telemetry is unavailable after any incomplete
                                        // record; never retry or append repair bytes.
                                        break;
                                    }
                                }
                            }
                        }
                    }
                    thread::sleep(Duration::from_millis(50));
                }
            })
            .ok();
        result
    }
}
impl Drop for FinancialProgressReporter {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Release);
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}
fn nonblocking_financial_progress_output() -> Option<std::fs::File> {
    use std::os::{fd::AsRawFd, unix::fs::OpenOptionsExt};
    let output = std::fs::OpenOptions::new()
        .write(true)
        .custom_flags(libc::O_NONBLOCK | libc::O_CLOEXEC | libc::O_NOCTTY)
        .open("/proc/self/fd/2")
        .ok()?;
    let mut original = std::mem::MaybeUninit::<libc::stat>::uninit();
    let mut opened = std::mem::MaybeUninit::<libc::stat>::uninit();
    // SAFETY: both stat buffers are valid writable storage; descriptors are
    // borrowed for inspection only and no flags on inherited stderr change.
    let valid = unsafe {
        libc::fstat(2, original.as_mut_ptr()) == 0
            && libc::fstat(output.as_raw_fd(), opened.as_mut_ptr()) == 0
    };
    if !valid {
        return None;
    }
    // SAFETY: successful fstat initialized both structures above.
    let (original, opened) = unsafe { (original.assume_init(), opened.assume_init()) };
    if (original.st_dev, original.st_ino, original.st_rdev)
        != (opened.st_dev, opened.st_ino, opened.st_rdev)
    {
        return None;
    }
    let kind = opened.st_mode & libc::S_IFMT;
    // Regular files can block despite O_NONBLOCK. Accept only this inherited
    // pipe or TTY endpoint, never a newly selected diagnostic destination.
    if kind != libc::S_IFIFO
        && !(kind == libc::S_IFCHR && unsafe { libc::isatty(output.as_raw_fd()) } == 1)
    {
        return None;
    }
    let flags = unsafe { libc::fcntl(output.as_raw_fd(), libc::F_GETFL) };
    if flags < 0 || flags & libc::O_NONBLOCK == 0 {
        return None;
    }
    Some(output)
}
