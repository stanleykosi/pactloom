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
    DurableAdmissionCallFailureV1, DurableAdmissionCallbackStageV1,
    DurableAdmissionDispatchFailureV1, DurableAdmissionDispatchStageV1,
    DurableAdmissionHistoryFailureV1, DurableAdmissionPreparationFailureV1,
    DurableAdmissionPreparationStageV1, DurableNativeEntryFailureV1, DurableNativeEntryStageV1,
    DurableNativeRecordsV1, DurableAcquireReplyLossV1, DurableFlowFailureV1, DurableFlowResultV1,
    EphemeralAcknowledgedBornV1, EphemeralDurableNativeV1, EphemeralDurableDeliveryNativeV2,
    EphemeralExportedBirthV1, EphemeralFirstAnchorIntentV1, EphemeralFirstAnchorPublicationV1,
    EphemeralOriginalRosterIntentV1, EphemeralPendingBornV1, EphemeralRosterPublicationV1,
    OriginalBirthSetupV1,
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
    DropUnselectedAnchor(usize),
    OpenDelivery(usize, wholepact_core::ProposalInput),
    DeliveryPeer(usize),
    PollDeliveryPair(usize),
    AcceptDelivery(usize),
    ConfigureDeliveryWitness(usize),
    PollDeliveryRedisclosure(usize, DurableConstructionRedisclosureRequestV1, Arc<AtomicBool>),
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
    Pending(EphemeralPendingBornV1),
    ExportedBirth(EphemeralExportedBirthV1),
    Acknowledged(EphemeralAcknowledgedBornV1),
    SingleIntent(EphemeralFirstAnchorIntentV1),
    SinglePublication(EphemeralFirstAnchorPublicationV1, bool),
    RosterIntent(EphemeralOriginalRosterIntentV1),
    RosterPublication(EphemeralRosterPublicationV1, bool),
    Durable(Box<EphemeralDurableNativeV1>),
    Delivery(Box<EphemeralDurableDeliveryNativeV2>),
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
        accounts.map(|account| Some(State::Pending(account))),
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

fn command_index(command: &JoinedSignerCommandV1) -> usize {
    use JoinedSignerCommandV1 as C;
    match command {
        C::ServeOriginalEvidence(_) => 0,
        C::DropUnselectedAnchor(i)
        | C::OpenDelivery(i, _)
        | C::DeliveryPeer(i)
        | C::PollDeliveryPair(i)
        | C::AcceptDelivery(i)
        | C::ConfigureDeliveryWitness(i)
        | C::PollDeliveryRedisclosure(i, _, _)
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

fn execute(
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
            let entry = account
                .open_fresh_durable_delivery_v2(proposal, 1_000_000)
                .map_err(durable_entry_error)?;
            let reply = delivery_peer(index, &entry)?;
            (State::Delivery(Box::new(entry)), reply)
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
                        diagnostic::emit_delivery_observation(B::DeliveryRedisclosure, diagnostic::signer_error(&error));
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
        (C::PollDeliveryImport(_, request, identity), State::Delivery(mut entry)) => {
            poll_until(
                entry
                    .deadline()
                    .map_err(|error| signer_error(error, "delivery import deadline"))?,
                cancelled,
                || {
                    let result = entry.poll_exact_import(&request, &identity);
                    if let Some(failure) = entry.take_failure() {
                        return Err(delivery_failure_error(failure));
                    }
                    result
                },
                "exact delivery native source import",
            )?;
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
            let exported = account
                .export_owner_request()
                .map_err(|error| signer_error(error, "native birth request sign and export"))?;
            let reply = R::BirthExport {
                index,
                account_id: exported.account_id().into(),
                birth_digest: exported.birth_digest().into(),
                exported_file: exported.exported_file().into(),
            };
            (State::ExportedBirth(exported), reply)
        }
        (C::Acknowledge(_), State::ExportedBirth(exported)) => {
            let account = exported.acknowledge_original().map_err(|error| {
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
            (State::Acknowledged(account), reply)
        }
        (C::OpenSingleIntent(_, intent), State::Acknowledged(account)) if index == 0 => {
            let entry = account
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
            (State::SingleIntent(entry), reply)
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
            let exported = entry
                .export_original_single()
                .map_err(|error| signer_error(error, "native single owner signature and export"))?;
            let reply = R::SingleExport {
                index,
                signed_extension_file: exported.signed_extension_file().into(),
                enrollment_request: exported.enrollment_request().clone(),
            };
            (
                State::Acknowledged(exported.close_for_witness_review()),
                reply,
            )
        }
        (C::OpenSinglePublication(_, request), State::Acknowledged(account)) if index == 0 => {
            let entry = account
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
            (State::SinglePublication(entry, false), reply)
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
            State::Acknowledged(entry.close_for_continuation()),
            R::Done { index },
        ),
        (C::OpenRosterIntent(_, intent), State::Acknowledged(account)) if index > 0 => {
            let entry = account
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
            (State::RosterIntent(entry), reply)
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
            let exported = entry.export_original_roster().map_err(|error| {
                signer_error(error, "native roster owner signature and exact exports")
            })?;
            let reply = R::RosterExport {
                index,
                signed_extension_file: exported.signed_extension_file().into(),
                original_policy_file: exported.original_policy_file().into(),
                enrollment_request: exported.enrollment_request().clone(),
            };
            (
                State::Acknowledged(exported.close_for_witness_review()),
                reply,
            )
        }
        (C::OpenRosterPublication(_, request), State::Acknowledged(account)) if index > 0 => {
            let entry = account
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
            (State::RosterPublication(entry, false), reply)
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
            State::Acknowledged(entry.close_for_continuation()),
            R::Done { index },
        ),

        (C::OpenDurable(_, proposal), State::Acknowledged(account)) if index > 0 => {
            let entry = account
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
            let entry = account
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
            (State::Acknowledged(account), R::Done { index })
        }
        _ => return Err("durable finite native transition mismatch"),
    };
    *slot = Some(next);
    Ok(reply)
}

#[cfg(test)]
mod admission_diagnostic_tests {
    use super::*;

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
