//! Finite public diagnostics for a private-transcript synthetic PTY test.
//! Only exact enum labels cross the transcript boundary. No error Display/Debug,
//! path, review text, account identifier, receipt, credential or artifact is copied.
use crate::{Error, Result};

macro_rules! labels {
    ($name:ident { $($variant:ident),+ $(,)? }) => {
        #[derive(Clone, Copy)]
        pub(super) enum $name { $($variant),+ }
        impl $name {
            fn label(self) -> &'static str { match self { $(Self::$variant => stringify!($variant)),+ } }
            fn parse(value: &str) -> Option<Self> { match value { $(stringify!($variant) => Some(Self::$variant)),+, _ => None } }
        }
    };
}
labels! { Boundary {
    SignerAdmissionCallCallerDeadline, SignerAdmissionCallExchangeDeadline, SignerAdmissionCallSourceCallback, SignerAdmissionCallBounds,
    SignerAdmissionCallRequestValidation, SignerAdmissionCallBinding, SignerAdmissionCallConnect, SignerAdmissionCallHandshake, SignerAdmissionCallPeerBinding, SignerAdmissionCallRequestBuild, SignerAdmissionCallRequestWrite, SignerAdmissionCallResponseRead, SignerAdmissionCallResponse, SignerAdmissionCallSnapshotValidation, SignerAdmissionCallCommittedHeadValidation, SignerAdmissionCallFinalValidation, SignerAdmissionDispatchFixtureState, SignerAdmissionDispatchReviewCorrelation, SignerAdmissionDispatchNativeApproval, SignerAdmissionDispatchIntentRetention, SignerAdmissionDispatchSubmitCustody, SignerAdmissionDispatchSubmitIntent, SignerAdmissionDispatchSubmitInterval, SignerAdmissionDispatchSubmitWorkspace, SignerAdmissionDispatchAuthorityCall, SignerAdmissionDispatchWorkerCompletion, SignerAdmissionDispatchCommittedCorrelation, SignerAdmissionCallbackWorkspaceCurrent, SignerAdmissionCallbackCustody, SignerAdmissionCallbackRequestValidation, SignerAdmissionCallIoTimeout, SignerAdmissionCallIoClosed, SignerAdmissionCallIoRefused, SignerAdmissionCallIoOther, SignerAdmissionCallCallbackError,
    SignerAdmissionHistoryCallerDeadline, SignerAdmissionHistoryExchangeDeadline, SignerAdmissionHistorySourceCallback, SignerAdmissionHistorySnapshotConnect, SignerAdmissionHistorySnapshotHandshake, SignerAdmissionHistorySnapshotPeerBinding, SignerAdmissionHistorySnapshotRequestBuild, SignerAdmissionHistorySnapshotRequestWrite, SignerAdmissionHistorySnapshotResponseRead, SignerAdmissionHistorySnapshotResponse, SignerAdmissionHistorySnapshotValidation, SignerAdmissionHistoryPageConnect, SignerAdmissionHistoryPageHandshake, SignerAdmissionHistoryPagePeerBinding, SignerAdmissionHistoryPageRequestBuild, SignerAdmissionHistoryPageRequestWrite, SignerAdmissionHistoryPageResponseRead, SignerAdmissionHistoryPageResponse, SignerAdmissionHistoryPageValidation, SignerAdmissionHistoryEventReplay, SignerAdmissionHistoryFinalValidation, SignerAdmissionHistoryBounds, SignerAdmissionHistoryIoTimeout, SignerAdmissionHistoryIoClosed, SignerAdmissionHistoryIoRefused, SignerAdmissionHistoryIoOther, SignerAdmissionHistoryCallbackError,
    SignerAdmissionFixtureState, SignerAdmissionSource, SignerAdmissionHistory, SignerAdmissionRetainedIntent, SignerAdmissionTerms, SignerAdmissionRequestBuilder, SignerAdmissionExactRequest, SignerAdmissionLiveInterval, SignerAdmissionLocalIntent, SignerAdmissionIntentDisplay, SignerAdmissionReviewCustody, SignerAdmissionReviewDisplay, SignerAdmissionNativeStage, SignerAdmissionWorkerCompletion,
    DurableHostWitnessSetup, DurableHostWriterReconcile, DurableHostViewingSetup, DurableHostSign, DurableHostSignRetry, DurableHostResultHistory, DurableHostResultRetrieve, DurableHostResultRelay, DurableHostSignatureIntake, DurableHostSignatureStatus, DurableHostResultServiceStop, DurableHostSignatureUnion, DurableHostTransactionCheckpoint,
    DurableHostOpen, DurableHostPairStatus, DurableHostPairObserved, DurableHostAccept, DurableHostInitialDisclosure, DurableHostInitialObserved, DurableHostRecipient, DurableHostCaptureSetup, DurableHostCapture, DurableHostCaptureObserved, DurableHostCaptureCommitted, DurableHostIntake, DurableHostClose, DurableHostObserve, DurableHostCheckpoint, DurableHostProof, DurableHostFreeze, DurableHostReload, DurableHostRedisclosure, DurableHostReviewReady, DurableHostReviewExport, DurableHostReviewImported, DurableHostProviderStop,
    DurableEntryNativeOwnerCheck, DurableEntryVaultOpen, DurableEntryRetainedEnrollment, DurableEntryOriginalCommit, DurableEntryJournalOpen, DurableEntrySourceCheck, DurableEntryRuntimeActivation, DurableEntryWorkerResult, DurableEntryEndpointCreate, DurableEntryEndpointBind, DurableEntryEndpointPublish, DurableEntryPostEndpointSourceCheck, DurableEntryFixturePreflight, DurableEntryFixturePostActivation,
    ObservationClockRollback, ObservationClockWallExpired, ObservationClockMonotonicExpired, ObservationRetainedClockRead, ObservationRetainedClockDenied, ObservationAdmittedClockRead, ObservationAdmittedClockDenied,
    CompletionObservationDenied, CompletionPostReentryCurrent, CompletionReadBinding, CompletionConstructionTime, CompletionCallerBinding, CompletionConstructionRequest,
    EngineCheckpointClaim, EngineCheckpointPlan, EngineCheckpointRetained, EngineCheckpointParts, EngineCheckpointNative, EngineCheckpointHeld, EngineCheckpointRestriction, EngineCheckpointConstruct, EngineCheckpointInspect, EngineCheckpointActionLimit, EngineCheckpointConsent, EngineCheckpointReceipt, EngineCheckpointRecord, EngineCheckpointEnqueue, EngineCheckpointFinish, EngineCheckpointContext,
    CheckpointEngine, CheckpointWalletUnwind, CheckpointFinish, CheckpointObservations, CheckpointOutput, CheckpointBeforeClaim, CheckpointClaimMayExist,
    SignerPollCancelled, SignerPollDeadline, SignerPollTerminal, RosterConstructionIntoNamed, RosterConstructionNamedOwner, RosterConstructionFinalOwner,
    RosterConstructionCheck, RosterConstructionReserve, RosterConstructionReservedAppend, RosterConstructionConsume, RosterConstructionConsumedAppend, RosterConstructionSend,
    ConstructionClockTerminal, ConstructionClockLiveness, ConstructionClockWallRollback, ConstructionClockWallExpired, ConstructionClockMonotonicExpired, RosterCompletionClaimCheck, RosterCompletionClaimSign, RosterCompletionClaimGranted, RosterCompletionClaimClaim, RosterCompletionClaimClaimed, RosterCompletionClaimObserve, RosterCompletionClaimHistory, RosterCompletionClaimReentered, RosterCompletionClaimSend,
    NativeOwnerRevoked, NativeOwnerExpired, NativeOwnerParent, NativeOwnerRetirementParent, RosterOwnerEpoch, RosterWorkOpenCommonContext, RosterWorkPrepareCompletionWitness, RosterWorkPrepareReenteredConstruction, RosterWorkCommitCompletionPair, RosterWorkCommitCompletionWitness, RosterWorkCommitCompletionClaim, RosterWorkCommitReenteredConstruction, RosterCompletionWitnessCheck, RosterCompletionWitnessHistory, RosterCompletionWitnessHistoryBinding, RosterCompletionWitnessTransport,
    CompletionOriginal, CompletionPairApproval, CompletionPairBegin, CompletionPairFinish, CompletionReentryRequest, CompletionRequestApproval, CompletionReentryBegin, CompletionReentryFinish, CompletionConstructionBegin, CompletionConstructionFinish,
    RosterBirthHistoryGate, RosterBirthExtension, RosterBirthOriginal, RosterBirthLinkage, ContinuationRetainedSource, ContinuationAttemptedSource, ContinuationWriterSource, ContinuationHistoryReplay, ContinuationPairing, ContinuationPreparedReview, ContinuationSource, ContinuationBirthLink, ContinuationPreconstruction, ContinuationHistoryGate, ContinuationHistoryArchive, ContinuationRetainedReceipt, ContinuationPreviousLoad, ContinuationProposalCapacity, ContinuationProposalIndex, ContinuationAttemptSequence, ContinuationProposalValidation,
    ObservedPlanWitnessOrigin, WitnessPlanInput, WitnessPlanSelect, WitnessPlanInputUtf8, WitnessPlanPublicRefusal, WitnessPlanQualifiedEntry, WitnessPlanLaunch, WitnessPlanDrain, WitnessPlanPending, WitnessPlanApprove, WitnessPlanReceipt, WitnessPlanReceiptDigest, WitnessPlanExpectedParse, WitnessPlanDigestMatch, WitnessPlanWorkerPrepare, WitnessPlanWorkerApprove,
    CandidateRetainCurrent, CandidateRetainRequest, CandidateRetainBegin, CandidateRetainFinish, CandidateLeaseOrigin, CandidateRequestRemaining,
    InventoryLeaseOrigin, InventoryRequestSource, InventoryRequestProvenance, InventoryRequestBinding, InventoryRequestRemaining,
    InventorySourceOwner, InventorySourceNative, InventorySourceDeadline, InventorySourcePeer, InventorySourceOwnerBinding, InventorySourcePeerBinding, InventorySourceRetiredGrant, InventorySourceProcess, InventorySourceRetained, InventorySourceAdmission, InventorySourceHistory, InventorySourceWitness, InventoryWindowWallRollback, InventoryWindowWallExpired, InventoryWindowMonotonicExpired, InventoryNativeBinding, InventorySourceRequest, InventoryPeerConnection, InventoryObservedMissing, InventoryObservedLifetimeInvalid, InventoryObservedWallRollback, InventoryObservedSessionExpired, InventoryObservedAgeExpired,
    ScanAccessAccount, ScanAccessNativeBefore, ScanAccessRequest, ScanAccessTarget, ScanAccessHostAccess, ScanAccessPrincipal, ScanAccessEnrollmentPrincipal, ScanAccessRequestDigest, ScanAccessScopeDigest, ScanAccessImport, ScanAccessNativeAfter, ScanNativeAdmissionDeadline, ScanNativeLease, ScanNativeRemaining, ScanNativePurpose, ScanNativeAccount, ScanNativeProviderSource, ScanNativeProviderEndpoint, ScanNativeProviderTrust,
    RosterWorkOpen, RosterWorkPrepareIntent, RosterWorkPrepareReentry, RosterWorkPrepareSignature, RosterWorkPrepareExport, RosterWorkPrepareWitness, RosterWorkPrepareAcquire, RosterWorkPrepareActivate, RosterWorkPreparePublication, RosterWorkPrepareServe, RosterWorkPrepareContinuationProposal, RosterWorkPrepareContinuationSign, RosterWorkPrepareContinuationExport, RosterWorkPrepareContinuedReentry, RosterWorkPrepareContinuedServe, RosterWorkPreparePolicyExport, RosterWorkPrepareInventory, RosterWorkPrepareCandidateSelection, RosterWorkRetryAdmission, RosterWorkRetryContinuedAdmission, RosterWorkRetryAcquire, RosterWorkRetryActivate, RosterWorkCommitPair, RosterWorkCommitRetain, RosterWorkCommitReentry, RosterWorkCommitSign, RosterWorkCommitExport, RosterWorkCommitWitness, RosterWorkCommitAcquire, RosterWorkCommitActivate, RosterWorkCommitAdmit, RosterWorkCommitPublish, RosterWorkCommitServe, RosterWorkCommitContinuationProposal, RosterWorkCommitContinuationSign, RosterWorkCommitContinuationExport, RosterWorkCommitContinuedReentry, RosterWorkCommitContinuedAdmit, RosterWorkCommitContinuedServe, RosterWorkCommitPolicyExport, RosterWorkCommitInventory, RosterWorkCommitCandidateSelection, RosterWorkCommitContributionRetention, RosterWorkOther, RosterWorkReceiveResult, RosterWorkAdoptOutput, RosterClearFocus, RosterClearOwner, RosterClearPeer, RosterClearInitialStream, RosterClearContinuedStream, RosterClearReviewExpired, RosterDropLateOutput,
    JoinedPairFinish, JoinedRequestBegin, JoinedLeaseFinish, JoinedInventoryCheck, JoinedAuditAppend, JoinedInventoryRun, InventoryPair, InventoryRequest, InventoryLease, InventoryImport, InventoryImportRecord, InventoryScan, InventorySynchronize, InventoryInspect, InventoryDisplay, InventoryFinish, CandidateRun, CandidatePair, CandidateRequest, CandidateLease, CandidateExclusions, CandidateSelect, CandidateDisplay, CandidateRetain, CandidateAttach,
    FullOriginalPolicy, RetainedPredecessor, RetainedMaterial, RetainedEconomics, RetainedInvocation, RetainedRuntime, RetainedProvider, RetainedTls, RetainedWitness, RetainedPolicyRead, RetainedPolicyMatch, RetainedSelectionFiles, ContinuedPredecessor, ContinuedObservation, ContinuedOriginal, ContinuedWait, ContinuedPrepare, Bootstrap, Session, PublicRefusal, PaymentReceiver, AgreementInput, AgreementNative, WitnessSetup, WitnessOrigin, SignerStart, BirthExport, BirthRead, BirthEnroll, BirthHistory, BirthAcknowledge, BirthDistinct, SinglePrepare, SingleOpen, SinglePair, SingleSubmit, SingleExport, SingleWitness, SinglePublicationPrepare, SingleHistory, SinglePublicationOpen, SinglePublicationPair, SingleFinish, SingleClose, RosterPrepare, RosterOpen, RosterPair, RosterSubmit, RosterExport, RosterWitness, RosterPublicationPrepare, RosterHistory, RosterPublicationOpen, RosterPublicationPair, RosterFinish, RosterClose, MetadataCheck, FinancialRefusal, EndInvariant, SignerCreate, SignerExportBirth, SignerAcknowledge, SignerOpenSingleIntent, SignerPollSingleIntent, SignerExportSingle, SignerOpenSinglePublication, SignerPollSinglePublication, SignerCloseSinglePublication, SignerOpenRosterIntent, SignerPollRosterIntent, SignerExportRoster, SignerOpenRosterPublication, SignerPollRosterPublication, SignerCloseRosterPublication, SignerOpenContinuationIntent, SignerPollContinuationIntent, SignerOpenContinuedPublication, SignerPollContinuedPublication, SignerCloseContinuedPublication, SignerExportOriginalFullPlan, SignerOpenCommonContextRead, SignerPollCommonContextRead, SignerParkCommonContextCompletion, SignerPeerMetadata, SignerNativeEntry, SignerEndpoint, SignerProvider, SignerDeadline, SignerSingleController, ObservedInputs, ObservedRetainedPredecessor, ObservedAssemble, ObservedCandidateReview, ObservedPlanExport, ObservedPlanSign, ObservedPlanRead, ObservedPlanAuthenticate, ObservedPlanWitness, ObservedContinuation, ObservedOwnerSplit, ObservedReadPrepare, ObservedReadHistory, ObservedReadOpen, ObservedReadPair, ObservedReadFinish, ObservedReadPark, ObservedBarrier, ObservedProviderDrain, ConstructedPredecessor, ConstructedDisclosure, ConstructedWitnessOriginal, ConstructedWitnessGrant, ConstructedWitnessScope, ConstructedPendingFile, ConstructedPendingReview, ConstructedSignerOpen, ConstructedConsume, ConstructedSignerPark, ConstructedServerSeal, ConstructedCheckpoint, ConstructedSavedOriginal, ConstructedInvariant, ConstructedProviderDrain, SignerOpenOriginalCompletion, SignerPollOriginalCompletion, ProvedConstructionDrain, ProvedOriginalJob, ProvedOriginalCorrelation, ProvedHostPublic, ProvedWitnessKey, ProvedNamedOpen, ProvedNamedPair, ProvedNamedStatus, ProvedNamedRecords, ProvedNamedProfile, ProvedNativePins, ProvedCarrierPrepare, ProvedCarrierExport, ProvedCarrierRecover, ProvedCarrierRetained, ProvedCarrierInvariant, SignerOpenOriginalNamed, SignerPollOriginalNamed, SignerRetainOriginalProfile, SignerNamedEnrollmentExport, SignerNamedInstalledMetadata, SignerNamedVerifierArm, SignerNamedVerifierStart, SignerNamedVerifierPoll, SignerNamedAssertionExport, SignerNamedOriginalImport, SignerNamedOriginalSubmit, SignerNamedOriginalSign, SignerNamedHostServing, FullPaymentPredecessor, FullEnrollmentExport, FullEnrollmentInstall, FullArtifactsInstall, FullInstalledMetadata, FullVerifierRequest, FullAssertion, FullOriginalImport, FullAdmission, FullSignatureReturn, FullHistory, FullReturnIntake, FullMerge, FullCurrentDispatch, FullRecipientReceipt, SingleAccountUnlock, SingleRetainedRead, SingleAcquireState, SingleAttemptedSource, SingleAttemptsRead, SingleRetainedReopen, SinglePreacquire, SingleReference, SingleAccountId, SingleAudit, SingleEndpointCreate, SingleDirectoryOpen, SingleIpcBind, SingleEndpointPublish, SingleWorkOpen, SingleWorkPrepareIntent, SingleWorkPrepareSignature, SingleWorkPrepareExport, SingleWorkPrepareReentry, SingleWorkPrepareWitness, SingleWorkPrepareAcquire, SingleWorkPrepareActivate, SingleWorkPreparePublication, SingleWorkPrepareServe, SingleWorkCommitPair, SingleWorkCommitRetain, SingleWorkCommitSignature, SingleWorkCommitExport, SingleWorkCommitReentry, SingleWorkCommitWitness, SingleWorkCommitAcquire, SingleWorkCommitActivate, SingleWorkCommitAdmission, SingleWorkCommitPublication, SingleWorkCommitServe, SingleWorkRetryAcquire, SingleWorkRetryActivate, SingleWorkRetryAdmission, SingleWorkOther, SingleWorkAdoptOutput
} }
labels! { Outcome {
    ExactPermission, ExactLineage, ExactBinding, ExactStorage, ExactRecoveryRequired, ExactStateChanged, ExactProfileChanged, ExactBudget, ExactRoster,
    EngineAccessDenied, EngineCandidateVerificationFailed, EngineIdempotencyConflict, EngineInvalidRequest, EngineInvalidTransition, EngineLiveAuthorizationExists, EngineManualConstructionDenied, EngineNotFound, EngineRecoveryRequired, EngineResourceExhausted, EngineRetainedObservationUnavailable, EngineRevisionConflict, EngineStorageProtectionRequired, EngineStorageUnavailable, EngineUnclassified, JobConsentDenied, JobIdempotencyConflict, JobInvalidRequest, JobNotFound, JobRecoveryRequired, JobResourceExhausted, JobStateConflict, JobStorage, JobUnsupportedSchema, JobVerificationFailed, ProtocolActionMapping, ProtocolBuilderInput, ProtocolBuilderOutput, ProtocolContext, ProtocolContribution, ProtocolDisclosure, ProtocolFee, ProtocolFinalize, ProtocolInput, ProtocolManifest, ProtocolOutput, ProtocolPczt, ProtocolUnclassified, StoreAlreadyExists, StoreBudgetExceeded, StoreDatabase, StoreEncoding, StoreFile, StoreIdempotencyConflict, StoreInputReserved, StoreInvalidInput, StoreInvalidTransition, StoreLiveAuthorizationExists, StoreNotFound, StorePoisoned, StoreRecoveryRequired, StoreResourceExhausted, StoreRevisionConflict, StoreStorageSecurity, StoreUnsupportedSchema, StoreWriterEpochMismatch,
    BridgeBinding, BridgeConflict, BridgeMissing, BridgeUncertain, BridgeLimit, BridgePermission, BridgeRecoveryRequired, BridgeCompleteOriginRecoveryUnavailable, BridgeVerification, BridgeSignerOriginUnavailable, BridgeJournal, BridgeAuthority, BridgeWallet, BridgeIpc,
    AuthorityInputEmpty, AuthorityInputWithinBound, AuthorityInputOverBound, AuthorityInvalidBinding, AuthorityPermission, AuthorityStaleHead, AuthorityConflict, AuthorityInactive, AuthorityRecoveryRequired, AuthorityExpired, AuthorityPolicyDenied, AuthorityBudgetExceeded, AuthorityInputReserved, AuthorityObligationReserved, AuthorityLimit, AuthorityStorage, AuthorityCorruptHistory, AuthorityPermanentStopUnavailable, AuthorityOfflineHistoryUnsupported, AuthorityConstructionHistoryUnsupported, AuthorityUnsupportedVersion, AuthorityAuthentication, AuthorityUncertain, AuthorityResolutionUnavailable, AuthoritySessionRequired, AuthoritySessionPending,
    OriginPermanentStopUnavailable, OriginRetirementEvidenceUnavailable, OriginSignerOriginUnavailable, OriginPeerLifetimeUnavailable, OriginAuthentication, OriginBinding, OriginConflict, OriginPermission, OriginInvalidData, OriginLocked, OriginCrypto, OriginIpc, OriginLimit, OriginIoTimedOut, OriginIoWouldBlock, OriginIoUnexpectedEof, OriginIoBrokenPipe, OriginIoConnectionReset, OriginIoConnectionAborted, OriginIoNotConnected, OriginIoInterrupted, OriginIoPermissionDenied, OriginIoOther,
    ImportFreshOwnerRequired, ImportBinding, ImportIncomplete, ImportStorage, SyncAccessDenied, SyncInvalidRequest, SyncInterrupted, SyncReconciliationRequired, SyncInvalidResponse, SyncResourceLimit, SyncNoCurrentObservation, WalletStorage, WalletAccountScope, WalletAccountMismatch, WalletIncompleteSync, WalletUnsupportedProfile, WalletChainMismatch, WalletInsufficientFunds, WalletInvalidRequest, WalletMissingWitness, WalletInvalidNote, WalletScan, WalletTransport, ChainInvalidConfiguration, ChainWrongNetwork, ChainUnsupportedProxyConfiguration, ChainWrongBranch, ChainStaleChain, ChainContradictoryChain, ChainTimeout, ChainTransportUnavailable, ChainObservationInterrupted, ChainMissingAncestryEvidence, ChainNotObserved, ChainResourceLimit, ChainMalformedEvidence, ChainUnsupportedCapability, ChainBackendFailure, ChainClockUnavailable, ChainIdempotencyConflict, ChainJournalFailure, ChainSubmissionNotAuthorized, ChainSubmissionExpiryMargin, ChainObligationConflict, ChainSubmissionOutcomeUnrecorded, ChainSubmissionRetentionUncertain, RecoveryAccessDenied, RecoveryUnsupportedAccountComponents, RecoveryIncompleteScan, RecoveryKnownFundsRemain, RecoveryAdditionalEvidenceRequired,
    Begin, Complete, HostPlatform, HostTerminal, HostPermission, HostLocked, HostInvalid, HostAuthentication, HostStorage, HostQuarantined, HostUnsupported, HostReceipt, HostRecoverySemantic, HostRecoveryBackupUnsupported, HostRecoveryFinancialUnsupported, HostCompleteOriginRecoveryUnavailable, HostHistoricalExportIncomplete, HostGenerationArchiveIncomplete, SignerUnavailable, SignerPeerLifetimeUnavailable, SignerIo, SignerAuthentication, SignerInvalidData, SignerCrypto, SignerLocked, SignerBackupRequired, SignerRecoveryRequired, SignerAlreadyOpen, SignerReviewMismatch, SignerVerification, SignerUncertain, SignerConsentJournal, SignerStore, WorkerFailure
} }

pub(super) fn emit(boundary: Boundary, outcome: Outcome) {
    eprintln!(
        "\n[JOINED_DIAGNOSTIC {} {}]",
        boundary.label(),
        outcome.label()
    );
}

#[cfg(feature = "synthetic-born-joined-qualification")]
use wholepact_authority::transport::history_diagnostics_v1::{
    CheckedHistoryCheckSiteV1, CheckedHistoryCheckpointV1, CheckedHistoryCostV1,
    CheckedHistoryMeasurementV1, CheckedHistoryPhaseV1, CheckedHistorySelectedLimitV1,
};

#[cfg(feature = "synthetic-born-joined-qualification")]
fn history_phase_label(value: CheckedHistoryPhaseV1) -> &'static str {
    match value {
        CheckedHistoryPhaseV1::Snapshot => "Snapshot",
        CheckedHistoryPhaseV1::Page => "Page",
        CheckedHistoryPhaseV1::Admission => "Admission",
        CheckedHistoryPhaseV1::Acquire => "Acquire",
        CheckedHistoryPhaseV1::Activate => "Activate",
        CheckedHistoryPhaseV1::Verify => "Verify",
        CheckedHistoryPhaseV1::Reserve => "Reserve",
    }
}

#[cfg(feature = "synthetic-born-joined-qualification")]
fn history_check_site_label(value: CheckedHistoryCheckSiteV1) -> &'static str {
    match value {
        CheckedHistoryCheckSiteV1::ReplayInitial => "ReplayInitial",
        CheckedHistoryCheckSiteV1::ReplayAfterSnapshot => "ReplayAfterSnapshot",
        CheckedHistoryCheckSiteV1::ReplayBeforePage => "ReplayBeforePage",
        CheckedHistoryCheckSiteV1::ReplayAfterPage => "ReplayAfterPage",
        CheckedHistoryCheckSiteV1::ReplayFinal => "ReplayFinal",
        CheckedHistoryCheckSiteV1::ExchangeInitial => "ExchangeInitial",
        CheckedHistoryCheckSiteV1::BeforeConnect => "BeforeConnect",
        CheckedHistoryCheckSiteV1::AfterConnect => "AfterConnect",
        CheckedHistoryCheckSiteV1::BeforeHandshakeIo => "BeforeHandshakeIo",
        CheckedHistoryCheckSiteV1::AfterHandshake => "AfterHandshake",
        CheckedHistoryCheckSiteV1::AfterPeerBinding => "AfterPeerBinding",
        CheckedHistoryCheckSiteV1::AfterRequestBuild => "AfterRequestBuild",
        CheckedHistoryCheckSiteV1::BeforeRequestWrite => "BeforeRequestWrite",
        CheckedHistoryCheckSiteV1::AfterRequestWrite => "AfterRequestWrite",
        CheckedHistoryCheckSiteV1::AfterResponseRead => "AfterResponseRead",
    }
}

#[cfg(feature = "synthetic-born-joined-qualification")]
fn history_checkpoint_label(value: CheckedHistoryCheckpointV1) -> &'static str {
    match value {
        CheckedHistoryCheckpointV1::EntryDeadline => "EntryDeadline",
        CheckedHistoryCheckpointV1::DeadlineSelection => "DeadlineSelection",
        CheckedHistoryCheckpointV1::ConnectRemaining => "ConnectRemaining",
        CheckedHistoryCheckpointV1::BeforeCallback => "BeforeCallback",
        CheckedHistoryCheckpointV1::Callback => "Callback",
        CheckedHistoryCheckpointV1::AfterCallback => "AfterCallback",
        CheckedHistoryCheckpointV1::Operation => "Operation",
        CheckedHistoryCheckpointV1::Validation => "Validation",
    }
}

#[cfg(feature = "synthetic-born-joined-qualification")]
fn history_selected_limit_label(value: CheckedHistorySelectedLimitV1) -> &'static str {
    match value {
        CheckedHistorySelectedLimitV1::Caller => "Caller",
        CheckedHistorySelectedLimitV1::Exchange => "Exchange",
    }
}

// Only these bounded primitive getters and finite labels may cross this boundary.
// The original error, request/response, endpoints and clocks are never serialized.
#[cfg(feature = "synthetic-born-joined-qualification")]
fn history_cost_json(value: &CheckedHistoryCostV1) -> serde_json::Value {
    serde_json::json!({
        "callback_calls": value.callback_calls(),
        "callback_us": value.callback_us(),
        "callback_max_us": value.callback_max_us(),
        "connect_calls": value.connect_calls(),
        "connect_us": value.connect_us(),
        "handshake_calls": value.handshake_calls(),
        "handshake_us": value.handshake_us(),
        "frame_write_calls": value.frame_write_calls(),
        "frame_write_us": value.frame_write_us(),
        "frame_read_calls": value.frame_read_calls(),
        "frame_read_us": value.frame_read_us(),
    })
}

#[cfg(feature = "synthetic-born-joined-qualification")]
fn history_measurement_json(value: &CheckedHistoryMeasurementV1) -> serde_json::Value {
    // Exchange cost is a subset of history cost, not another additive interval.
    serde_json::json!({
        "version": 1,
        "phase": value.phase().map(history_phase_label),
        "page_ordinal": value.page_ordinal(),
        "check_site": value.check_site().map(history_check_site_label),
        "checkpoint": history_checkpoint_label(value.checkpoint()),
        "selected_limit": value.selected_limit().map(history_selected_limit_label),
        "selected_budget_us": value.selected_budget_us(),
        "caller_remaining_at_budget_start_us": value.caller_remaining_at_budget_start_us(),
        "caller_remaining_at_failure_us": value.caller_remaining_at_failure_us(),
        "selected_remaining_at_failure_us": value.selected_remaining_at_failure_us(),
        "history_elapsed_us": value.history_elapsed_us(),
        "exchange_elapsed_us": value.exchange_elapsed_us(),
        "pre_budget_callback_calls": value.pre_budget_callback_calls(),
        "pre_budget_callback_us": value.pre_budget_callback_us(),
        "history_cost": history_cost_json(value.history_cost()),
        "exchange_cost": value.exchange_cost().map(history_cost_json),
        "clamped": value.clamped(),
        "incomplete": value.incomplete(),
    })
}

#[cfg(feature = "synthetic-born-joined-qualification")]
pub(super) fn emit_history_measurement(value: &CheckedHistoryMeasurementV1) {
    if !matches!(
        value.phase(),
        None | Some(CheckedHistoryPhaseV1::Snapshot | CheckedHistoryPhaseV1::Page)
    ) {
        return;
    }
    use std::io::Write;
    let _ = writeln!(
        std::io::stderr().lock(),
        "\n[HISTORY_MEASUREMENT_V1 {}]",
        history_measurement_json(value)
    );
}

#[cfg(feature = "synthetic-born-joined-qualification")]
#[derive(Clone, Copy)]
pub(super) enum HistoryServerMeasurementPoint {
    BeforeAdmission,
    AfterAdmission,
}

#[cfg(feature = "synthetic-born-joined-qualification")]
fn history_server_measurement_json(
    point: HistoryServerMeasurementPoint,
    age_us: Option<u64>,
    remaining_us: u64,
    stopped: bool,
    finished: Option<bool>,
    clamped: bool,
) -> serde_json::Value {
    const MAX_US: u64 = 600_000_000;
    let clamped = clamped || age_us.is_some_and(|value| value > MAX_US) || remaining_us > MAX_US;
    let point = match point {
        HistoryServerMeasurementPoint::BeforeAdmission => "BeforeAdmission",
        HistoryServerMeasurementPoint::AfterAdmission => "AfterAdmission",
    };
    serde_json::json!({
        "version": 1,
        "point": point,
        "age_us": age_us.map(|value| value.min(MAX_US)),
        "remaining_us": remaining_us.min(MAX_US),
        "stopped": stopped,
        "finished": finished,
        "clamped": clamped,
    })
}

#[cfg(feature = "synthetic-born-joined-qualification")]
pub(super) fn emit_history_server_measurement(
    point: HistoryServerMeasurementPoint,
    age_us: Option<u64>,
    remaining_us: u64,
    stopped: bool,
    finished: Option<bool>,
    clamped: bool,
) {
    use std::io::Write;
    let _ = writeln!(
        std::io::stderr().lock(),
        "\n[HISTORY_SERVER_MEASUREMENT_V1 {}]",
        history_server_measurement_json(point, age_us, remaining_us, stopped, finished, clamped)
    );
}

// The PTY boundary must parse before retaining or re-emitting anything. These
// private DTOs cannot carry errors, timestamps, endpoints, or payload fields.
// Every nullable field is required: serde's normal missing-Option default is
// deliberately disabled by deserialize_with. Derive also rejects duplicates.
#[cfg(feature = "synthetic-born-joined-qualification")]
fn required_history_nullable<'de, D, T>(deserializer: D) -> std::result::Result<Option<T>, D::Error>
where
    D: serde::Deserializer<'de>,
    T: serde::Deserialize<'de>,
{
    <Option<T> as serde::Deserialize>::deserialize(deserializer)
}

#[cfg(feature = "synthetic-born-joined-qualification")]
#[derive(serde::Deserialize, serde::Serialize)]
#[serde(deny_unknown_fields)]
struct PublicHistoryCost {
    callback_calls: u32,
    callback_us: u32,
    callback_max_us: u32,
    connect_calls: u32,
    connect_us: u32,
    handshake_calls: u32,
    handshake_us: u32,
    frame_write_calls: u32,
    frame_write_us: u32,
    frame_read_calls: u32,
    frame_read_us: u32,
}

#[cfg(feature = "synthetic-born-joined-qualification")]
impl PublicHistoryCost {
    fn valid(&self) -> bool {
        [
            self.callback_calls,
            self.connect_calls,
            self.handshake_calls,
            self.frame_write_calls,
            self.frame_read_calls,
        ]
        .into_iter()
        .all(|value| value <= 1_000_000)
            && [
                self.callback_us,
                self.callback_max_us,
                self.connect_us,
                self.handshake_us,
                self.frame_write_us,
                self.frame_read_us,
            ]
            .into_iter()
            .all(|value| value <= 600_000_000)
    }
}

#[cfg(feature = "synthetic-born-joined-qualification")]
#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct PublicHistoryMeasurement {
    version: u8,
    #[serde(deserialize_with = "required_history_nullable")]
    phase: Option<String>,
    #[serde(deserialize_with = "required_history_nullable")]
    page_ordinal: Option<u16>,
    #[serde(deserialize_with = "required_history_nullable")]
    check_site: Option<String>,
    checkpoint: String,
    #[serde(deserialize_with = "required_history_nullable")]
    selected_limit: Option<String>,
    #[serde(deserialize_with = "required_history_nullable")]
    selected_budget_us: Option<u32>,
    #[serde(deserialize_with = "required_history_nullable")]
    caller_remaining_at_budget_start_us: Option<u32>,
    #[serde(deserialize_with = "required_history_nullable")]
    caller_remaining_at_failure_us: Option<u32>,
    #[serde(deserialize_with = "required_history_nullable")]
    selected_remaining_at_failure_us: Option<u32>,
    history_elapsed_us: u32,
    #[serde(deserialize_with = "required_history_nullable")]
    exchange_elapsed_us: Option<u32>,
    pre_budget_callback_calls: u8,
    pre_budget_callback_us: u32,
    history_cost: PublicHistoryCost,
    #[serde(deserialize_with = "required_history_nullable")]
    exchange_cost: Option<PublicHistoryCost>,
    clamped: bool,
    incomplete: bool,
}

#[cfg(feature = "synthetic-born-joined-qualification")]
impl PublicHistoryMeasurement {
    fn valid(&self) -> bool {
        let _ = (self.clamped, self.incomplete); // Flags never establish success.
        self.version == 1
            && matches!(self.phase.as_deref(), None | Some("Snapshot" | "Page"))
            && self
                .page_ordinal
                .is_none_or(|value| (1..=4096).contains(&value))
            && (self.phase.as_deref() == Some("Page")) == self.page_ordinal.is_some()
            && matches!(
                self.check_site.as_deref(),
                None | Some(
                    "ReplayInitial"
                        | "ReplayAfterSnapshot"
                        | "ReplayBeforePage"
                        | "ReplayAfterPage"
                        | "ReplayFinal"
                        | "ExchangeInitial"
                        | "BeforeConnect"
                        | "AfterConnect"
                        | "BeforeHandshakeIo"
                        | "AfterHandshake"
                        | "AfterPeerBinding"
                        | "AfterRequestBuild"
                        | "BeforeRequestWrite"
                        | "AfterRequestWrite"
                        | "AfterResponseRead"
                )
            )
            && matches!(
                self.checkpoint.as_str(),
                "EntryDeadline"
                    | "DeadlineSelection"
                    | "ConnectRemaining"
                    | "BeforeCallback"
                    | "Callback"
                    | "AfterCallback"
                    | "Operation"
                    | "Validation"
            )
            && matches!(
                self.selected_limit.as_deref(),
                None | Some("Caller" | "Exchange")
            )
            && [
                self.selected_budget_us,
                self.caller_remaining_at_budget_start_us,
                self.caller_remaining_at_failure_us,
                self.selected_remaining_at_failure_us,
                self.exchange_elapsed_us,
            ]
            .into_iter()
            .all(|value| value.is_none_or(|value| value <= 600_000_000))
            && self.history_elapsed_us <= 600_000_000
            && self.pre_budget_callback_calls <= 1
            && self.pre_budget_callback_us <= 600_000_000
            && self.history_cost.valid()
            && self
                .exchange_cost
                .as_ref()
                .is_none_or(PublicHistoryCost::valid)
    }
}

#[cfg(feature = "synthetic-born-joined-qualification")]
#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct PublicHistoryServerMeasurement {
    version: u8,
    point: String,
    #[serde(deserialize_with = "required_history_nullable")]
    age_us: Option<u32>,
    remaining_us: u32,
    stopped: bool,
    #[serde(deserialize_with = "required_history_nullable")]
    finished: Option<bool>,
    clamped: bool,
}

#[cfg(feature = "synthetic-born-joined-qualification")]
impl PublicHistoryServerMeasurement {
    fn valid(&self) -> bool {
        let _ = (self.stopped, self.finished, self.clamped); // Observations, not readiness.
        self.version == 1
            && matches!(self.point.as_str(), "BeforeAdmission" | "AfterAdmission")
            && self.age_us.is_none_or(|value| value <= 600_000_000)
            && self.remaining_us <= 600_000_000
    }
}

#[cfg(feature = "synthetic-born-joined-qualification")]
enum PublicHistoryRecord {
    Client(String),
    ServerBefore(String),
    ServerAfter(String),
}

#[cfg(feature = "synthetic-born-joined-qualification")]
impl PublicHistoryRecord {
    fn line(&self) -> &str {
        match self {
            Self::Client(line) | Self::ServerBefore(line) | Self::ServerAfter(line) => line,
        }
    }
    fn slot(&self) -> usize {
        match self {
            Self::Client(_) => 0,
            Self::ServerBefore(_) => 1,
            Self::ServerAfter(_) => 2,
        }
    }
}

#[cfg(feature = "synthetic-born-joined-qualification")]
fn parse_history_record(line: &str, server: bool) -> Option<PublicHistoryRecord> {
    let prefix = if server {
        "[HISTORY_SERVER_MEASUREMENT_V1 "
    } else {
        "[HISTORY_MEASUREMENT_V1 "
    };
    let text = line.strip_prefix(prefix)?.strip_suffix(']')?;
    if text.len() > if server { 512 } else { 4096 } {
        return None;
    }
    let slot = if server {
        let value: PublicHistoryServerMeasurement = serde_json::from_str(text).ok()?;
        if !value.valid() {
            return None;
        }
        if value.point == "BeforeAdmission" {
            1
        } else {
            2
        }
    } else {
        let value: PublicHistoryMeasurement = serde_json::from_str(text).ok()?;
        if !value.valid() {
            return None;
        }
        0
    };
    // Only after the strict DTO rejected missing/duplicate/extra/nonfinite data
    // may a canonical primitive JSON object be retained. Never retain raw text.
    let value: serde_json::Value = serde_json::from_str(text).ok()?;
    let canonical = format!("{prefix}{value}]");
    Some(match slot {
        0 => PublicHistoryRecord::Client(canonical),
        1 => PublicHistoryRecord::ServerBefore(canonical),
        _ => PublicHistoryRecord::ServerAfter(canonical),
    })
}

#[cfg(feature = "synthetic-born-joined-qualification")]
#[derive(Default)]
pub(super) struct HistoryMeasurementCapture {
    records: [Option<PublicHistoryRecord>; 3],
    client_invalid: bool,
    server_invalid: bool,
}

#[cfg(feature = "synthetic-born-joined-qualification")]
impl HistoryMeasurementCapture {
    pub(super) fn retained_bytes(&self) -> usize {
        self.records
            .iter()
            .flatten()
            .map(|record| record.line().len())
            .sum()
    }

    pub(super) fn discard_for_budget(&mut self) {
        if self.records.iter().any(Option::is_some) {
            self.client_invalid = true;
            self.server_invalid = true;
        }
        self.records = Default::default();
    }

    pub(super) fn capture_line(&mut self, line: &str, available: usize) {
        let server = if line.starts_with("[HISTORY_SERVER_MEASUREMENT_V1 ") {
            true
        } else if line.starts_with("[HISTORY_MEASUREMENT_V1 ") {
            false
        } else {
            return;
        };
        if if server {
            self.server_invalid
        } else {
            self.client_invalid
        } {
            return;
        }
        let parsed = parse_history_record(line, server);
        if let Some(record) = parsed {
            let slot = record.slot();
            if self.records[slot].is_none() && record.line().len() <= available {
                self.records[slot] = Some(record);
                return;
            }
        }
        if server {
            self.server_invalid = true;
            self.records[1] = None;
            self.records[2] = None;
        } else {
            self.client_invalid = true;
            self.records[0] = None;
        }
    }

    pub(super) fn public_lines(&self) -> Vec<&str> {
        let mut lines = Vec::with_capacity(3);
        if self.client_invalid {
            lines.push("CI_SYNTHETIC_HISTORY_MEASUREMENT invalid=true details_withheld=true");
        } else if let Some(record) = &self.records[0] {
            lines.push(record.line());
        }
        if self.server_invalid {
            lines
                .push("CI_SYNTHETIC_HISTORY_SERVER_MEASUREMENT invalid=true details_withheld=true");
        } else {
            for record in self.records[1..].iter().flatten() {
                lines.push(record.line());
            }
        }
        lines
    }
}

// Admission records use their own exact schema and slots. The historical wire
// never accepts Admission. All nested timings are inclusive, not additive.

#[cfg(feature = "synthetic-born-joined-qualification")]
use wholepact_signer::native_ui::synthetic_born_joined_qualification::{
    DurableAdmissionDispatchFailureV1, DurableAdmissionDispatchStageV1,
    DurableAdmissionCompletionV1, DurableAdmissionRetentionV1, DurableAdmissionCallbackStageV1,
    DurableAdmissionDispatchMeasurementV1,
};

#[cfg(feature = "synthetic-born-joined-qualification")]
use wholepact_authority::transport::{
    history_diagnostics_v1::CheckedHistoryIoKindV1,
    admission_diagnostics_v1::{
        AdmissionWitnessDiagnosticV1, AdmissionWitnessErrorV1, AdmissionWitnessStageV1,
        AdmissionWitnessAttributionV1, AdmissionWitnessResultV1, AdmissionWitnessCompletionV1,
        AdmissionWitnessCommitV1, AdmissionWitnessReceiptGateV1, AdmissionWitnessCorrelationV1,
        AdmissionWitnessSpanV1, AdmissionWitnessCostV1,
    },
};

#[cfg(feature = "synthetic-born-joined-qualification")]
fn signer_admission_stage_label(value: DurableAdmissionDispatchStageV1) -> &'static str {
    match value {
        DurableAdmissionDispatchStageV1::FixtureState => "FixtureState",
        DurableAdmissionDispatchStageV1::ReviewCorrelation => "ReviewCorrelation",
        DurableAdmissionDispatchStageV1::NativeApproval => "NativeApproval",
        DurableAdmissionDispatchStageV1::IntentRetention => "IntentRetention",
        DurableAdmissionDispatchStageV1::SubmitCustody => "SubmitCustody",
        DurableAdmissionDispatchStageV1::SubmitIntent => "SubmitIntent",
        DurableAdmissionDispatchStageV1::SubmitInterval => "SubmitInterval",
        DurableAdmissionDispatchStageV1::SubmitWorkspace => "SubmitWorkspace",
        DurableAdmissionDispatchStageV1::AuthorityCall => "AuthorityCall",
        DurableAdmissionDispatchStageV1::WorkerCompletion => "WorkerCompletion",
        DurableAdmissionDispatchStageV1::CommittedCorrelation => "CommittedCorrelation",
    }
}

#[cfg(feature = "synthetic-born-joined-qualification")]
fn signer_admission_completion_label(value: DurableAdmissionCompletionV1) -> &'static str {
    match value {
        DurableAdmissionCompletionV1::NotObserved => "NotObserved",
        DurableAdmissionCompletionV1::ReturnedOk => "ReturnedOk",
        DurableAdmissionCompletionV1::ReturnedErr => "ReturnedErr",
        DurableAdmissionCompletionV1::Missing => "Missing",
        DurableAdmissionCompletionV1::Invalidated => "Invalidated",
        DurableAdmissionCompletionV1::Disconnected => "Disconnected",
    }
}

#[cfg(feature = "synthetic-born-joined-qualification")]
fn signer_admission_retention_label(value: DurableAdmissionRetentionV1) -> &'static str {
    match value {
        DurableAdmissionRetentionV1::NotObserved => "NotObserved",
        DurableAdmissionRetentionV1::Unconfirmed => "Unconfirmed",
        DurableAdmissionRetentionV1::Confirmed => "Confirmed",
    }
}

#[cfg(feature = "synthetic-born-joined-qualification")]
fn signer_admission_callback_stage_label(value: DurableAdmissionCallbackStageV1) -> &'static str {
    match value {
        DurableAdmissionCallbackStageV1::WorkspaceCurrent => "WorkspaceCurrent",
        DurableAdmissionCallbackStageV1::Custody => "Custody",
        DurableAdmissionCallbackStageV1::RequestValidation => "RequestValidation",
    }
}

#[cfg(feature = "synthetic-born-joined-qualification")]
fn witness_admission_stage_label(value: AdmissionWitnessStageV1) -> &'static str {
    match value {
        AdmissionWitnessStageV1::SourceArm => "SourceArm",
        AdmissionWitnessStageV1::ServerCreate => "ServerCreate",
        AdmissionWitnessStageV1::ListenerAccept => "ListenerAccept",
        AdmissionWitnessStageV1::ResultLookup => "ResultLookup",
        AdmissionWitnessStageV1::SocketBinding => "SocketBinding",
        AdmissionWitnessStageV1::WaitCurrent => "WaitCurrent",
        AdmissionWitnessStageV1::TlsSetup => "TlsSetup",
        AdmissionWitnessStageV1::TlsHandshake => "TlsHandshake",
        AdmissionWitnessStageV1::PeerBinding => "PeerBinding",
        AdmissionWitnessStageV1::FrameRead => "FrameRead",
        AdmissionWitnessStageV1::SemanticDispatch => "SemanticDispatch",
        AdmissionWitnessStageV1::JournalPreflight => "JournalPreflight",
        AdmissionWitnessStageV1::ExactRequest => "ExactRequest",
        AdmissionWitnessStageV1::Publication => "Publication",
        AdmissionWitnessStageV1::Apply => "Apply",
        AdmissionWitnessStageV1::Append => "Append",
        AdmissionWitnessStageV1::FinalCurrent => "FinalCurrent",
        AdmissionWitnessStageV1::Commit => "Commit",
        AdmissionWitnessStageV1::ControlledResult => "ControlledResult",
        AdmissionWitnessStageV1::SnapshotRecord => "SnapshotRecord",
        AdmissionWitnessStageV1::OutputCheck => "OutputCheck",
        AdmissionWitnessStageV1::FrameWrite => "FrameWrite",
        AdmissionWitnessStageV1::CloseFlush => "CloseFlush",
        AdmissionWitnessStageV1::WorkerDisplay => "WorkerDisplay",
        AdmissionWitnessStageV1::FixtureDrain => "FixtureDrain",
        AdmissionWitnessStageV1::FixtureReceipt => "FixtureReceipt",
        AdmissionWitnessStageV1::FixtureCorrelation => "FixtureCorrelation",
    }
}

#[cfg(feature = "synthetic-born-joined-qualification")]
fn witness_admission_attribution_label(value: AdmissionWitnessAttributionV1) -> &'static str {
    match value {
        AdmissionWitnessAttributionV1::SelectedServer => "SelectedServer",
        AdmissionWitnessAttributionV1::ExactRequest => "ExactRequest",
    }
}

#[cfg(feature = "synthetic-born-joined-qualification")]
fn witness_admission_result_label(value: AdmissionWitnessResultV1) -> &'static str {
    match value {
        AdmissionWitnessResultV1::NotObserved => "NotObserved",
        AdmissionWitnessResultV1::ReturnedOk => "ReturnedOk",
        AdmissionWitnessResultV1::ReturnedErr => "ReturnedErr",
    }
}

#[cfg(feature = "synthetic-born-joined-qualification")]
fn witness_admission_completion_label(value: AdmissionWitnessCompletionV1) -> &'static str {
    match value {
        AdmissionWitnessCompletionV1::NotObserved => "NotObserved",
        AdmissionWitnessCompletionV1::Received => "Received",
        AdmissionWitnessCompletionV1::Disconnected => "Disconnected",
        AdmissionWitnessCompletionV1::Panicked => "Panicked",
    }
}

#[cfg(feature = "synthetic-born-joined-qualification")]
fn witness_admission_commit_label(value: AdmissionWitnessCommitV1) -> &'static str {
    match value {
        AdmissionWitnessCommitV1::NotObserved => "NotObserved",
        AdmissionWitnessCommitV1::Entered => "Entered",
        AdmissionWitnessCommitV1::ReturnedOk => "ReturnedOk",
        AdmissionWitnessCommitV1::ReturnedErr => "ReturnedErr",
    }
}

#[cfg(feature = "synthetic-born-joined-qualification")]
fn witness_admission_receipt_gate_label(value: AdmissionWitnessReceiptGateV1) -> &'static str {
    match value {
        AdmissionWitnessReceiptGateV1::NotObserved => "NotObserved",
        AdmissionWitnessReceiptGateV1::Unfocused => "Unfocused",
        AdmissionWitnessReceiptGateV1::EpochMismatch => "EpochMismatch",
        AdmissionWitnessReceiptGateV1::Revoked => "Revoked",
        AdmissionWitnessReceiptGateV1::Closing => "Closing",
        AdmissionWitnessReceiptGateV1::ClockRejected => "ClockRejected",
        AdmissionWitnessReceiptGateV1::Retained => "Retained",
    }
}

#[cfg(feature = "synthetic-born-joined-qualification")]
fn witness_admission_correlation_label(value: AdmissionWitnessCorrelationV1) -> &'static str {
    match value {
        AdmissionWitnessCorrelationV1::NotObserved => "NotObserved",
        AdmissionWitnessCorrelationV1::Matched => "Matched",
        AdmissionWitnessCorrelationV1::Rejected => "Rejected",
    }
}

#[cfg(feature = "synthetic-born-joined-qualification")]
fn admission_io_kind_label(value: CheckedHistoryIoKindV1) -> &'static str {
    match value {
        CheckedHistoryIoKindV1::Timeout => "Timeout",
        CheckedHistoryIoKindV1::Closed => "Closed",
        CheckedHistoryIoKindV1::Refused => "Refused",
        CheckedHistoryIoKindV1::Other => "Other",
    }
}

#[cfg(feature = "synthetic-born-joined-qualification")]
fn admission_measurement_json(value: &CheckedHistoryMeasurementV1) -> serde_json::Value {
    // Exchange cost is nested in operation cost; this is the same checked kernel.
    serde_json::json!({
        "version": 1,
        "phase": value.phase().map(history_phase_label),
        "check_site": value.check_site().map(history_check_site_label),
        "checkpoint": history_checkpoint_label(value.checkpoint()),
        "selected_limit": value.selected_limit().map(history_selected_limit_label),
        "selected_budget_us": value.selected_budget_us(),
        "caller_remaining_at_budget_start_us": value.caller_remaining_at_budget_start_us(),
        "caller_remaining_at_failure_us": value.caller_remaining_at_failure_us(),
        "selected_remaining_at_failure_us": value.selected_remaining_at_failure_us(),
        "operation_elapsed_us": value.history_elapsed_us(),
        "exchange_elapsed_us": value.exchange_elapsed_us(),
        "pre_budget_callback_calls": value.pre_budget_callback_calls(),
        "pre_budget_callback_us": value.pre_budget_callback_us(),
        "operation_cost": history_cost_json(value.history_cost()),
        "exchange_cost": value.exchange_cost().map(history_cost_json),
        "clamped": value.clamped(),
        "incomplete": value.incomplete(),
    })
}

#[cfg(feature = "synthetic-born-joined-qualification")]
fn signer_admission_measurement_json(
    value: &DurableAdmissionDispatchMeasurementV1,
) -> serde_json::Value {
    // Custody and request validation are inclusive callback subtimings.
    serde_json::json!({
        "native_approval_us": value.native_approval_us(),
        "retention_us": value.retention_us(),
        "submit_preflight_us": value.submit_preflight_us(),
        "callback_custody_us": value.callback_custody_us(),
        "callback_custody_max_us": value.callback_custody_max_us(),
        "request_validation_us": value.request_validation_us(),
        "request_validation_max_us": value.request_validation_max_us(),
        "callback_custody_calls": value.callback_custody_calls(),
        "request_validation_calls": value.request_validation_calls(),
        "clamped": value.clamped(),
        "incomplete": value.incomplete(),
    })
}

#[cfg(feature = "synthetic-born-joined-qualification")]
fn signer_admission_json(value: &DurableAdmissionDispatchFailureV1) -> serde_json::Value {
    serde_json::json!({
        "version": 1,
        "stage": signer_admission_stage_label(value.stage()),
        "completion": signer_admission_completion_label(value.completion()),
        "retention": signer_admission_retention_label(value.retention()),
        "original_error": value.original_error().map(|error| signer_error(error).label()),
        "callback_stage": value.call_failure().and_then(|failure| failure.callback_stage()).map(signer_admission_callback_stage_label),
        "measurement": value.measurement().map(signer_admission_measurement_json),
    })
}

#[cfg(feature = "synthetic-born-joined-qualification")]
fn witness_admission_error_json(value: &AdmissionWitnessErrorV1) -> serde_json::Value {
    serde_json::json!({
        "stage": witness_admission_stage_label(value.stage()),
        "attribution": witness_admission_attribution_label(value.attribution()),
        "io_kind": value.io_kind().map(admission_io_kind_label),
        "error": authority_error(&value.error()).label(),
    })
}

#[cfg(feature = "synthetic-born-joined-qualification")]
fn witness_admission_cost_json(value: &AdmissionWitnessCostV1) -> serde_json::Value {
    serde_json::json!({ "calls": value.calls(), "elapsed_us": value.elapsed_us() })
}

#[cfg(feature = "synthetic-born-joined-qualification")]
fn witness_admission_json(value: &AdmissionWitnessDiagnosticV1) -> serde_json::Value {
    // ReturnedOk commit, source snapshot and receipt are separate observations.
    serde_json::json!({
        "version": 1,
        "first_semantic": value.first_semantic().map(witness_admission_error_json),
        "first_connection": value.first_connection().map(witness_admission_error_json),
        "worker_result": witness_admission_result_label(value.worker_result()),
        "fixture_result": witness_admission_result_label(value.fixture_result()),
        "worker_error": value.worker_error().map(|error| authority_error(&error).label()),
        "fixture_error": value.fixture_error().map(|error| authority_error(&error).label()),
        "worker_stage": value.worker_stage().map(witness_admission_stage_label),
        "fixture_stage": value.fixture_stage().map(witness_admission_stage_label),
        "completion": witness_admission_completion_label(value.completion()),
        "commit": witness_admission_commit_label(value.commit()),
        "controlled_result": value.controlled_result(),
        "snapshot_recorded": value.snapshot_recorded(),
        "receipt_gate": witness_admission_receipt_gate_label(value.receipt_gate()),
        "final_correlation": witness_admission_correlation_label(value.final_correlation()),
        "cost": {
            "worker": witness_admission_cost_json(value.cost(AdmissionWitnessSpanV1::Worker)),
            "source_arm": witness_admission_cost_json(value.cost(AdmissionWitnessSpanV1::SourceArm)),
            "server_create": witness_admission_cost_json(value.cost(AdmissionWitnessSpanV1::ServerCreate)),
            "accept": witness_admission_cost_json(value.cost(AdmissionWitnessSpanV1::Accept)),
            "connection": witness_admission_cost_json(value.cost(AdmissionWitnessSpanV1::Connection)),
            "handshake": witness_admission_cost_json(value.cost(AdmissionWitnessSpanV1::Handshake)),
            "frame_read": witness_admission_cost_json(value.cost(AdmissionWitnessSpanV1::FrameRead)),
            "dispatch": witness_admission_cost_json(value.cost(AdmissionWitnessSpanV1::Dispatch)),
            "publication": witness_admission_cost_json(value.cost(AdmissionWitnessSpanV1::Publication)),
            "append": witness_admission_cost_json(value.cost(AdmissionWitnessSpanV1::Append)),
            "commit": witness_admission_cost_json(value.cost(AdmissionWitnessSpanV1::Commit)),
            "frame_write": witness_admission_cost_json(value.cost(AdmissionWitnessSpanV1::FrameWrite)),
            "fixture_finish": witness_admission_cost_json(value.cost(AdmissionWitnessSpanV1::FixtureFinish)),
        },
        "clamped": value.clamped(),
        "incomplete": value.incomplete(),
    })
}

#[cfg(feature = "synthetic-born-joined-qualification")]
pub(super) fn emit_admission_measurement(value: &CheckedHistoryMeasurementV1) {
    if !matches!(value.phase(), None | Some(CheckedHistoryPhaseV1::Admission)) {
        return;
    }
    emit_admission_record(0, admission_measurement_json(value));
}

#[cfg(feature = "synthetic-born-joined-qualification")]
pub(super) fn emit_signer_admission(value: &DurableAdmissionDispatchFailureV1) {
    emit_admission_record(1, signer_admission_json(value));
}

#[cfg(feature = "synthetic-born-joined-qualification")]
pub(super) fn emit_witness_admission(value: &AdmissionWitnessDiagnosticV1) {
    emit_admission_record(2, witness_admission_json(value));
}

#[cfg(feature = "synthetic-born-joined-qualification")]
fn emit_admission_record(slot: usize, value: serde_json::Value) {
    use std::io::Write;
    // Serialization/validation/write failure is optional telemetry loss only.
    let Ok(text) = serde_json::to_string(&value) else {
        return;
    };
    let line = format!("{}{text}]", ADMISSION_PREFIXES[slot]);
    let Some(record) = parse_admission_record(&line, slot) else {
        return;
    };
    let _ = writeln!(std::io::stderr().lock(), "\n{}", record.line);
}

#[cfg(feature = "synthetic-born-joined-qualification")]
#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct PublicAdmissionMeasurement {
    version: u8,
    #[serde(deserialize_with = "required_history_nullable")]
    phase: Option<String>,
    #[serde(deserialize_with = "required_history_nullable")]
    check_site: Option<String>,
    checkpoint: String,
    #[serde(deserialize_with = "required_history_nullable")]
    selected_limit: Option<String>,
    #[serde(deserialize_with = "required_history_nullable")]
    selected_budget_us: Option<u32>,
    #[serde(deserialize_with = "required_history_nullable")]
    caller_remaining_at_budget_start_us: Option<u32>,
    #[serde(deserialize_with = "required_history_nullable")]
    caller_remaining_at_failure_us: Option<u32>,
    #[serde(deserialize_with = "required_history_nullable")]
    selected_remaining_at_failure_us: Option<u32>,
    #[serde(deserialize_with = "required_history_nullable")]
    exchange_elapsed_us: Option<u32>,
    operation_elapsed_us: u32,
    pre_budget_callback_calls: u8,
    pre_budget_callback_us: u32,
    operation_cost: PublicHistoryCost,
    #[serde(deserialize_with = "required_history_nullable")]
    exchange_cost: Option<PublicHistoryCost>,
    clamped: bool,
    incomplete: bool,
}

#[cfg(feature = "synthetic-born-joined-qualification")]
impl PublicAdmissionMeasurement {
    fn valid(&self) -> bool {
        let _ = (self.clamped, self.incomplete);
        self.version == 1
            && matches!(self.phase.as_deref(), None | Some("Admission"))
            && matches!(
                self.check_site.as_deref(),
                None | Some(
                    "ExchangeInitial"
                        | "BeforeConnect"
                        | "AfterConnect"
                        | "BeforeHandshakeIo"
                        | "AfterHandshake"
                        | "AfterPeerBinding"
                        | "AfterRequestBuild"
                        | "BeforeRequestWrite"
                        | "AfterRequestWrite"
                        | "AfterResponseRead"
                )
            )
            && matches!(
                self.checkpoint.as_str(),
                "EntryDeadline"
                    | "DeadlineSelection"
                    | "ConnectRemaining"
                    | "BeforeCallback"
                    | "Callback"
                    | "AfterCallback"
                    | "Operation"
                    | "Validation"
            )
            && matches!(
                self.selected_limit.as_deref(),
                None | Some("Caller" | "Exchange")
            )
            && [
                self.selected_budget_us,
                self.caller_remaining_at_budget_start_us,
                self.caller_remaining_at_failure_us,
                self.selected_remaining_at_failure_us,
                self.exchange_elapsed_us,
            ]
            .into_iter()
            .all(admission_duration)
            && self.operation_elapsed_us <= 600_000_000
            && self.pre_budget_callback_calls <= 1
            && self.pre_budget_callback_us <= 600_000_000
            && self.operation_cost.valid()
            && self
                .exchange_cost
                .as_ref()
                .is_none_or(PublicHistoryCost::valid)
    }
}

#[cfg(feature = "synthetic-born-joined-qualification")]
fn admission_duration(value: Option<u32>) -> bool {
    value.is_none_or(|value| value <= 600_000_000)
}

#[cfg(feature = "synthetic-born-joined-qualification")]
#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct PublicSignerAdmissionMeasurement {
    #[serde(deserialize_with = "required_history_nullable")]
    native_approval_us: Option<u32>,
    #[serde(deserialize_with = "required_history_nullable")]
    retention_us: Option<u32>,
    #[serde(deserialize_with = "required_history_nullable")]
    submit_preflight_us: Option<u32>,
    #[serde(deserialize_with = "required_history_nullable")]
    callback_custody_us: Option<u32>,
    #[serde(deserialize_with = "required_history_nullable")]
    callback_custody_max_us: Option<u32>,
    #[serde(deserialize_with = "required_history_nullable")]
    request_validation_us: Option<u32>,
    #[serde(deserialize_with = "required_history_nullable")]
    request_validation_max_us: Option<u32>,
    #[serde(deserialize_with = "required_history_nullable")]
    callback_custody_calls: Option<u32>,
    #[serde(deserialize_with = "required_history_nullable")]
    request_validation_calls: Option<u32>,
    clamped: bool,
    incomplete: bool,
}

#[cfg(feature = "synthetic-born-joined-qualification")]
impl PublicSignerAdmissionMeasurement {
    fn valid(&self) -> bool {
        let _ = (self.clamped, self.incomplete);
        [
            self.native_approval_us,
            self.retention_us,
            self.submit_preflight_us,
            self.callback_custody_us,
            self.callback_custody_max_us,
            self.request_validation_us,
            self.request_validation_max_us,
        ]
        .into_iter()
        .all(admission_duration)
            && [self.callback_custody_calls, self.request_validation_calls]
                .into_iter()
                .all(|value| value.is_none_or(|value| value <= 1_000_000))
    }
}

#[cfg(feature = "synthetic-born-joined-qualification")]
#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct PublicSignerAdmission {
    version: u8,
    stage: String,
    completion: String,
    retention: String,
    #[serde(deserialize_with = "required_history_nullable")]
    original_error: Option<String>,
    #[serde(deserialize_with = "required_history_nullable")]
    callback_stage: Option<String>,
    #[serde(deserialize_with = "required_history_nullable")]
    measurement: Option<PublicSignerAdmissionMeasurement>,
}

#[cfg(feature = "synthetic-born-joined-qualification")]
impl PublicSignerAdmission {
    fn valid(&self) -> bool {
        self.version == 1
            && matches!(
                self.stage.as_str(),
                "FixtureState"
                    | "ReviewCorrelation"
                    | "NativeApproval"
                    | "IntentRetention"
                    | "SubmitCustody"
                    | "SubmitIntent"
                    | "SubmitInterval"
                    | "SubmitWorkspace"
                    | "AuthorityCall"
                    | "WorkerCompletion"
                    | "CommittedCorrelation"
            )
            && matches!(
                self.completion.as_str(),
                "NotObserved"
                    | "ReturnedOk"
                    | "ReturnedErr"
                    | "Missing"
                    | "Invalidated"
                    | "Disconnected"
            )
            && matches!(
                self.retention.as_str(),
                "NotObserved" | "Unconfirmed" | "Confirmed"
            )
            && matches!(
                self.original_error.as_deref(),
                None | Some(
                    "SignerUnavailable"
                        | "SignerPeerLifetimeUnavailable"
                        | "SignerIo"
                        | "SignerAuthentication"
                        | "SignerInvalidData"
                        | "SignerCrypto"
                        | "SignerLocked"
                        | "SignerBackupRequired"
                        | "SignerRecoveryRequired"
                        | "SignerAlreadyOpen"
                        | "SignerReviewMismatch"
                        | "SignerVerification"
                        | "SignerUncertain"
                        | "SignerConsentJournal"
                        | "SignerStore"
                )
            )
            && matches!(
                self.callback_stage.as_deref(),
                None | Some("WorkspaceCurrent" | "Custody" | "RequestValidation")
            )
            && self
                .measurement
                .as_ref()
                .is_none_or(PublicSignerAdmissionMeasurement::valid)
    }
}

#[cfg(feature = "synthetic-born-joined-qualification")]
fn valid_admission_authority_error(value: &str) -> bool {
    matches!(
        value,
        "AuthorityInvalidBinding"
            | "AuthorityPermission"
            | "AuthorityStaleHead"
            | "AuthorityConflict"
            | "AuthorityInactive"
            | "AuthorityRecoveryRequired"
            | "AuthorityExpired"
            | "AuthorityPolicyDenied"
            | "AuthorityBudgetExceeded"
            | "AuthorityInputReserved"
            | "AuthorityObligationReserved"
            | "AuthorityLimit"
            | "AuthorityStorage"
            | "AuthorityCorruptHistory"
            | "AuthorityPermanentStopUnavailable"
            | "AuthorityOfflineHistoryUnsupported"
            | "AuthorityConstructionHistoryUnsupported"
            | "AuthorityUnsupportedVersion"
            | "AuthorityAuthentication"
            | "AuthorityUncertain"
            | "AuthorityResolutionUnavailable"
            | "AuthoritySessionRequired"
            | "AuthoritySessionPending"
    )
}

#[cfg(feature = "synthetic-born-joined-qualification")]
fn valid_witness_admission_stage(value: &str) -> bool {
    matches!(
        value,
        "SourceArm"
            | "ServerCreate"
            | "ListenerAccept"
            | "ResultLookup"
            | "SocketBinding"
            | "WaitCurrent"
            | "TlsSetup"
            | "TlsHandshake"
            | "PeerBinding"
            | "FrameRead"
            | "SemanticDispatch"
            | "JournalPreflight"
            | "ExactRequest"
            | "Publication"
            | "Apply"
            | "Append"
            | "FinalCurrent"
            | "Commit"
            | "ControlledResult"
            | "SnapshotRecord"
            | "OutputCheck"
            | "FrameWrite"
            | "CloseFlush"
            | "WorkerDisplay"
            | "FixtureDrain"
            | "FixtureReceipt"
            | "FixtureCorrelation"
    )
}

#[cfg(feature = "synthetic-born-joined-qualification")]
#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct PublicWitnessAdmissionError {
    stage: String,
    attribution: String,
    #[serde(deserialize_with = "required_history_nullable")]
    io_kind: Option<String>,
    error: String,
}

#[cfg(feature = "synthetic-born-joined-qualification")]
impl PublicWitnessAdmissionError {
    fn valid(&self) -> bool {
        valid_witness_admission_stage(&self.stage)
            && matches!(self.attribution.as_str(), "SelectedServer" | "ExactRequest")
            && matches!(
                self.io_kind.as_deref(),
                None | Some("Timeout" | "Closed" | "Refused" | "Other")
            )
            && valid_admission_authority_error(&self.error)
    }
}

#[cfg(feature = "synthetic-born-joined-qualification")]
#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct PublicWitnessAdmissionCost {
    calls: u32,
    #[serde(deserialize_with = "required_history_nullable")]
    elapsed_us: Option<u32>,
}

#[cfg(feature = "synthetic-born-joined-qualification")]
impl PublicWitnessAdmissionCost {
    fn valid(&self) -> bool {
        self.calls <= 1_000_000 && admission_duration(self.elapsed_us)
    }
}

#[cfg(feature = "synthetic-born-joined-qualification")]
#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct PublicWitnessAdmissionCosts {
    worker: PublicWitnessAdmissionCost,
    source_arm: PublicWitnessAdmissionCost,
    server_create: PublicWitnessAdmissionCost,
    accept: PublicWitnessAdmissionCost,
    connection: PublicWitnessAdmissionCost,
    handshake: PublicWitnessAdmissionCost,
    frame_read: PublicWitnessAdmissionCost,
    dispatch: PublicWitnessAdmissionCost,
    publication: PublicWitnessAdmissionCost,
    append: PublicWitnessAdmissionCost,
    commit: PublicWitnessAdmissionCost,
    frame_write: PublicWitnessAdmissionCost,
    fixture_finish: PublicWitnessAdmissionCost,
}

#[cfg(feature = "synthetic-born-joined-qualification")]
impl PublicWitnessAdmissionCosts {
    fn valid(&self) -> bool {
        [
            &self.worker,
            &self.source_arm,
            &self.server_create,
            &self.accept,
            &self.connection,
            &self.handshake,
            &self.frame_read,
            &self.dispatch,
            &self.publication,
            &self.append,
            &self.commit,
            &self.frame_write,
            &self.fixture_finish,
        ]
        .into_iter()
        .all(PublicWitnessAdmissionCost::valid)
    }
}

#[cfg(feature = "synthetic-born-joined-qualification")]
#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct PublicWitnessAdmission {
    version: u8,
    #[serde(deserialize_with = "required_history_nullable")]
    first_semantic: Option<PublicWitnessAdmissionError>,
    #[serde(deserialize_with = "required_history_nullable")]
    first_connection: Option<PublicWitnessAdmissionError>,
    worker_result: String,
    fixture_result: String,
    #[serde(deserialize_with = "required_history_nullable")]
    worker_error: Option<String>,
    #[serde(deserialize_with = "required_history_nullable")]
    fixture_error: Option<String>,
    #[serde(deserialize_with = "required_history_nullable")]
    worker_stage: Option<String>,
    #[serde(deserialize_with = "required_history_nullable")]
    fixture_stage: Option<String>,
    completion: String,
    commit: String,
    #[serde(deserialize_with = "required_history_nullable")]
    controlled_result: Option<bool>,
    #[serde(deserialize_with = "required_history_nullable")]
    snapshot_recorded: Option<bool>,
    receipt_gate: String,
    final_correlation: String,
    cost: PublicWitnessAdmissionCosts,
    clamped: bool,
    incomplete: bool,
}

#[cfg(feature = "synthetic-born-joined-qualification")]
impl PublicWitnessAdmission {
    fn valid(&self) -> bool {
        let _ = (
            self.controlled_result,
            self.snapshot_recorded,
            self.clamped,
            self.incomplete,
        );
        self.version == 1
            && self
                .first_semantic
                .as_ref()
                .is_none_or(PublicWitnessAdmissionError::valid)
            && self
                .first_connection
                .as_ref()
                .is_none_or(PublicWitnessAdmissionError::valid)
            && self
                .worker_error
                .as_deref()
                .is_none_or(valid_admission_authority_error)
            && self
                .fixture_error
                .as_deref()
                .is_none_or(valid_admission_authority_error)
            && self
                .worker_stage
                .as_deref()
                .is_none_or(valid_witness_admission_stage)
            && self
                .fixture_stage
                .as_deref()
                .is_none_or(valid_witness_admission_stage)
            && matches!(
                self.worker_result.as_str(),
                "NotObserved" | "ReturnedOk" | "ReturnedErr"
            )
            && matches!(
                self.fixture_result.as_str(),
                "NotObserved" | "ReturnedOk" | "ReturnedErr"
            )
            && matches!(
                self.completion.as_str(),
                "NotObserved" | "Received" | "Disconnected" | "Panicked"
            )
            && matches!(
                self.commit.as_str(),
                "NotObserved" | "Entered" | "ReturnedOk" | "ReturnedErr"
            )
            && matches!(
                self.receipt_gate.as_str(),
                "NotObserved"
                    | "Unfocused"
                    | "EpochMismatch"
                    | "Revoked"
                    | "Closing"
                    | "ClockRejected"
                    | "Retained"
            )
            && matches!(
                self.final_correlation.as_str(),
                "NotObserved" | "Matched" | "Rejected"
            )
            && self.cost.valid()
    }
}

#[cfg(feature = "synthetic-born-joined-qualification")]
const ADMISSION_PREFIXES: [&str; 3] = [
    "[ADMISSION_MEASUREMENT_V1 ",
    "[SIGNER_ADMISSION_V1 ",
    "[WITNESS_ADMISSION_V1 ",
];
#[cfg(feature = "synthetic-born-joined-qualification")]
const ADMISSION_INVALID: [&str; 3] = [
    "CI_SYNTHETIC_ADMISSION_MEASUREMENT invalid=true details_withheld=true",
    "CI_SYNTHETIC_SIGNER_ADMISSION invalid=true details_withheld=true",
    "CI_SYNTHETIC_WITNESS_ADMISSION invalid=true details_withheld=true",
];
#[cfg(feature = "synthetic-born-joined-qualification")]
struct PublicAdmissionRecord {
    line: String,
}
#[cfg(feature = "synthetic-born-joined-qualification")]
fn parse_admission_record(line: &str, slot: usize) -> Option<PublicAdmissionRecord> {
    let prefix = *ADMISSION_PREFIXES.get(slot)?;
    let text = line.strip_prefix(prefix)?.strip_suffix(']')?;
    if text.len() > 4096 {
        return None;
    }
    let valid = match slot {
        0 => serde_json::from_str::<PublicAdmissionMeasurement>(text)
            .ok()?
            .valid(),
        1 => serde_json::from_str::<PublicSignerAdmission>(text)
            .ok()?
            .valid(),
        2 => serde_json::from_str::<PublicWitnessAdmission>(text)
            .ok()?
            .valid(),
        _ => return None,
    };
    if !valid {
        return None;
    }
    // Only strictly typed, fully checked primitive data can become canonical.
    let value: serde_json::Value = serde_json::from_str(text).ok()?;
    Some(PublicAdmissionRecord {
        line: format!("{prefix}{value}]"),
    })
}
#[cfg(feature = "synthetic-born-joined-qualification")]
#[derive(Default)]
pub(super) struct AdmissionDiagnosticCapture {
    records: [Option<PublicAdmissionRecord>; 3],
    invalid: [bool; 3],
}
#[cfg(feature = "synthetic-born-joined-qualification")]
impl AdmissionDiagnosticCapture {
    pub(super) fn retained_bytes(&self) -> usize {
        self.records
            .iter()
            .flatten()
            .map(|record| record.line.len())
            .sum()
    }
    pub(super) fn discard_for_budget(&mut self) {
        for slot in 0..3 {
            if self.records[slot].take().is_some() {
                self.invalid[slot] = true;
            }
        }
    }
    pub(super) fn capture_line(&mut self, line: &str, available: usize) {
        let Some(slot) = (0..3).find(|&slot| {
            line.starts_with(ADMISSION_PREFIXES[slot]) || line == ADMISSION_INVALID[slot]
        }) else {
            return;
        };
        if self.invalid[slot] {
            return;
        }
        if let Some(record) = parse_admission_record(line, slot) {
            if self.records[slot].is_none() && record.line.len() <= available {
                self.records[slot] = Some(record);
                return;
            }
        }
        self.records[slot] = None;
        self.invalid[slot] = true;
    }
    pub(super) fn public_lines(&self) -> Vec<&str> {
        (0..3)
            .filter_map(|slot| {
                if self.invalid[slot] {
                    Some(ADMISSION_INVALID[slot])
                } else {
                    self.records[slot]
                        .as_ref()
                        .map(|record| record.line.as_str())
                }
            })
            .collect()
    }
}

#[cfg(all(test, feature = "synthetic-born-joined-qualification"))]
pub(super) const ADMISSION_MEASUREMENT_TEST_JSON: &str = r#"{"version":1,"phase":"Admission","check_site":"AfterResponseRead","checkpoint":"AfterCallback","selected_limit":"Exchange","selected_budget_us":1000000,"caller_remaining_at_budget_start_us":2000000,"caller_remaining_at_failure_us":1000000,"selected_remaining_at_failure_us":0,"exchange_elapsed_us":1000000,"pre_budget_callback_calls":1,"pre_budget_callback_us":10,"exchange_cost":{"callback_calls":1,"callback_us":10,"callback_max_us":10,"connect_calls":1,"connect_us":30,"handshake_calls":1,"handshake_us":40,"frame_write_calls":1,"frame_write_us":50,"frame_read_calls":1,"frame_read_us":60},"clamped":false,"incomplete":false,"operation_elapsed_us":1000010,"operation_cost":{"callback_calls":2,"callback_us":20,"callback_max_us":10,"connect_calls":1,"connect_us":30,"handshake_calls":1,"handshake_us":40,"frame_write_calls":1,"frame_write_us":50,"frame_read_calls":1,"frame_read_us":60}}"#;

#[cfg(all(test, feature = "synthetic-born-joined-qualification"))]
pub(super) const SIGNER_ADMISSION_TEST_JSON: &str = r#"{"version":1,"stage":"AuthorityCall","completion":"ReturnedErr","retention":"Confirmed","original_error":"SignerAuthentication","callback_stage":"RequestValidation","measurement":{"native_approval_us":0,"retention_us":0,"submit_preflight_us":0,"callback_custody_us":0,"callback_custody_max_us":0,"request_validation_us":0,"request_validation_max_us":0,"callback_custody_calls":0,"request_validation_calls":0,"clamped":false,"incomplete":false}}"#;

#[cfg(all(test, feature = "synthetic-born-joined-qualification"))]
pub(super) const WITNESS_ADMISSION_TEST_JSON: &str = r#"{"version":1,"first_semantic":{"stage":"ExactRequest","attribution":"ExactRequest","io_kind":null,"error":"AuthorityInvalidBinding"},"first_connection":{"stage":"FrameWrite","attribution":"ExactRequest","io_kind":"Closed","error":"AuthorityAuthentication"},"worker_result":"ReturnedOk","fixture_result":"ReturnedErr","worker_error":null,"fixture_error":"AuthorityAuthentication","worker_stage":null,"fixture_stage":"FixtureReceipt","completion":"Received","commit":"ReturnedOk","controlled_result":true,"snapshot_recorded":true,"receipt_gate":"NotObserved","final_correlation":"NotObserved","cost":{"worker":{"calls":0,"elapsed_us":null},"source_arm":{"calls":0,"elapsed_us":null},"server_create":{"calls":0,"elapsed_us":null},"accept":{"calls":0,"elapsed_us":null},"connection":{"calls":0,"elapsed_us":null},"handshake":{"calls":0,"elapsed_us":null},"frame_read":{"calls":0,"elapsed_us":null},"dispatch":{"calls":0,"elapsed_us":null},"publication":{"calls":0,"elapsed_us":null},"append":{"calls":0,"elapsed_us":null},"commit":{"calls":0,"elapsed_us":null},"frame_write":{"calls":0,"elapsed_us":null},"fixture_finish":{"calls":0,"elapsed_us":null}},"clamped":false,"incomplete":false}"#;

#[cfg(all(test, feature = "synthetic-born-joined-qualification"))]
pub(super) const HISTORY_MEASUREMENT_TEST_JSON: &str = r#"{"version":1,"phase":"Snapshot","page_ordinal":null,"check_site":"AfterResponseRead","checkpoint":"AfterCallback","selected_limit":"Exchange","selected_budget_us":1000000,"caller_remaining_at_budget_start_us":2000000,"caller_remaining_at_failure_us":1000000,"selected_remaining_at_failure_us":0,"history_elapsed_us":1000010,"exchange_elapsed_us":1000000,"pre_budget_callback_calls":1,"pre_budget_callback_us":10,"history_cost":{"callback_calls":2,"callback_us":20,"callback_max_us":10,"connect_calls":1,"connect_us":30,"handshake_calls":1,"handshake_us":40,"frame_write_calls":1,"frame_write_us":50,"frame_read_calls":1,"frame_read_us":60},"exchange_cost":{"callback_calls":1,"callback_us":10,"callback_max_us":10,"connect_calls":1,"connect_us":30,"handshake_calls":1,"handshake_us":40,"frame_write_calls":1,"frame_write_us":50,"frame_read_calls":1,"frame_read_us":60},"clamped":false,"incomplete":false}"#;

#[test]
#[cfg(feature = "synthetic-born-joined-qualification")]
fn history_measurement_parser_requires_exact_bounded_fields() {
    let valid: serde_json::Value = serde_json::from_str(HISTORY_MEASUREMENT_TEST_JSON).unwrap();
    let line = format!("[HISTORY_MEASUREMENT_V1 {valid}]");
    assert!(parse_history_record(&line, false).is_some());
    for key in valid.as_object().unwrap().keys() {
        let mut missing = valid.clone();
        missing.as_object_mut().unwrap().remove(key);
        assert!(
            parse_history_record(&format!("[HISTORY_MEASUREMENT_V1 {missing}]"), false).is_none()
        );
    }
    for (key, value) in [
        ("version", serde_json::json!(true)),
        ("version", serde_json::json!(2)),
        ("phase", serde_json::json!("private")),
        ("page_ordinal", serde_json::json!(1)),
        ("check_site", serde_json::json!("private")),
        ("checkpoint", serde_json::json!("private")),
        ("selected_limit", serde_json::json!("private")),
        ("selected_budget_us", serde_json::json!(600_000_001u64)),
        ("history_elapsed_us", serde_json::json!(-1)),
        ("pre_budget_callback_calls", serde_json::json!(2)),
        ("clamped", serde_json::json!(0)),
        ("incomplete", serde_json::json!(null)),
        ("private", serde_json::json!("payload")),
    ] {
        let mut changed = valid.clone();
        changed[key] = value;
        assert!(
            parse_history_record(&format!("[HISTORY_MEASUREMENT_V1 {changed}]"), false).is_none()
        );
    }
    for key in valid["history_cost"].as_object().unwrap().keys() {
        let mut changed = valid.clone();
        changed["history_cost"][key] = serde_json::json!(true);
        assert!(
            parse_history_record(&format!("[HISTORY_MEASUREMENT_V1 {changed}]"), false).is_none()
        );
    }
    let duplicate =
        HISTORY_MEASUREMENT_TEST_JSON.replacen("\"version\":1", "\"version\":1,\"version\":1", 1);
    assert!(
        parse_history_record(&format!("[HISTORY_MEASUREMENT_V1 {duplicate}]"), false).is_none()
    );
    let duplicate = HISTORY_MEASUREMENT_TEST_JSON.replacen(
        "\"callback_calls\":2",
        "\"callback_calls\":2,\"callback_calls\":2",
        1,
    );
    assert!(
        parse_history_record(&format!("[HISTORY_MEASUREMENT_V1 {duplicate}]"), false).is_none()
    );
    for number in ["NaN", "Infinity", "-Infinity", "1.0"] {
        let changed = HISTORY_MEASUREMENT_TEST_JSON.replacen(
            "\"version\":1",
            &format!("\"version\":{number}"),
            1,
        );
        assert!(
            parse_history_record(&format!("[HISTORY_MEASUREMENT_V1 {changed}]"), false).is_none()
        );
    }
}

#[test]
#[cfg(feature = "synthetic-born-joined-qualification")]
fn history_server_measurement_projection_preserves_null_zero_and_caps() {
    let value = history_server_measurement_json(
        HistoryServerMeasurementPoint::BeforeAdmission,
        None,
        0,
        false,
        None,
        true,
    );
    assert!(value["age_us"].is_null());
    assert!(value["finished"].is_null());
    assert_eq!(value["remaining_us"], 0);
    assert_eq!(value["clamped"], true);
    let line = format!("[HISTORY_SERVER_MEASUREMENT_V1 {value}]");
    let record = parse_history_record(&line, true).unwrap();
    assert_eq!(record.slot(), 1);
    for key in value.as_object().unwrap().keys() {
        let mut missing = value.clone();
        missing.as_object_mut().unwrap().remove(key);
        assert!(
            parse_history_record(&format!("[HISTORY_SERVER_MEASUREMENT_V1 {missing}]"), true)
                .is_none()
        );
    }
    let value = history_server_measurement_json(
        HistoryServerMeasurementPoint::AfterAdmission,
        Some(u64::MAX),
        u64::MAX,
        true,
        Some(false),
        false,
    );
    assert_eq!(value["age_us"], 600_000_000);
    assert_eq!(value["remaining_us"], 600_000_000);
    assert_eq!(value["finished"], false);
    assert_eq!(value["clamped"], true);
    let record =
        parse_history_record(&format!("[HISTORY_SERVER_MEASUREMENT_V1 {value}]"), true).unwrap();
    assert_eq!(record.slot(), 2);
    for (key, invalid) in [
        ("point", serde_json::json!("Ready")),
        ("stopped", serde_json::json!(1)),
        ("finished", serde_json::json!(0)),
        ("remaining_us", serde_json::json!(600_000_001u64)),
        ("age_us", serde_json::json!(true)),
        ("private", serde_json::json!("payload")),
    ] {
        let mut changed = value.clone();
        changed[key] = invalid;
        assert!(
            parse_history_record(&format!("[HISTORY_SERVER_MEASUREMENT_V1 {changed}]"), true)
                .is_none()
        );
    }
    let text = value
        .to_string()
        .replacen("\"version\":1", "\"version\":1,\"version\":1", 1);
    assert!(
        parse_history_record(&format!("[HISTORY_SERVER_MEASUREMENT_V1 {text}]"), true).is_none()
    );
}

#[test]
#[cfg(feature = "synthetic-born-joined-qualification")]
fn history_measurement_capture_is_canonical_bounded_and_sticky() {
    let mut capture = HistoryMeasurementCapture::default();
    let line = format!("[HISTORY_MEASUREMENT_V1   {HISTORY_MEASUREMENT_TEST_JSON}  ]");
    capture.capture_line(&format!("private {line}"), 8192);
    assert!(capture.public_lines().is_empty());
    capture.capture_line(&line, 8192);
    assert_eq!(capture.public_lines().len(), 1);
    assert!(!capture.public_lines()[0].contains("  "));
    for point in [
        HistoryServerMeasurementPoint::BeforeAdmission,
        HistoryServerMeasurementPoint::AfterAdmission,
    ] {
        let value = history_server_measurement_json(point, Some(0), 0, false, Some(false), false);
        capture.capture_line(&format!("[HISTORY_SERVER_MEASUREMENT_V1 {value}]"), 8192);
    }
    assert_eq!(capture.public_lines().len(), 3);
    assert!(capture.retained_bytes() < 4096 + 2 * 512);
    capture.capture_line(&line, 8192);
    assert_eq!(capture.public_lines().len(), 3);
    assert!(capture.public_lines()[0].contains("invalid=true"));
    capture.capture_line(&line, 8192);
    assert!(capture.public_lines()[0].contains("invalid=true"));
    capture.discard_for_budget();
    assert_eq!(capture.retained_bytes(), 0);
    assert!(capture
        .public_lines()
        .iter()
        .all(|line| line.contains("invalid=true")));
    let mut capture = HistoryMeasurementCapture::default();
    capture.capture_line(&line, 1);
    capture.capture_line(&line, 8192);
    assert_eq!(capture.retained_bytes(), 0);
    assert!(capture.public_lines()[0].contains("invalid=true"));
    let mut capture = HistoryMeasurementCapture::default();
    capture.capture_line("[HISTORY_MEASUREMENT_V1 {\"private\":\"payload\"}]", 8192);
    assert_eq!(capture.retained_bytes(), 0);
    assert!(!capture.public_lines()[0].contains("payload"));
}

#[test]
#[cfg(feature = "synthetic-born-joined-qualification")]
fn history_measurement_parser_preserves_unavailable_and_exhausted() {
    let mut value: serde_json::Value = serde_json::from_str(HISTORY_MEASUREMENT_TEST_JSON).unwrap();
    for key in [
        "phase",
        "page_ordinal",
        "check_site",
        "selected_limit",
        "selected_budget_us",
        "caller_remaining_at_budget_start_us",
        "caller_remaining_at_failure_us",
        "selected_remaining_at_failure_us",
        "exchange_elapsed_us",
        "exchange_cost",
    ] {
        value[key] = serde_json::Value::Null;
    }
    value["incomplete"] = serde_json::json!(true);
    let record = parse_history_record(&format!("[HISTORY_MEASUREMENT_V1 {value}]"), false).unwrap();
    assert!(record
        .line()
        .contains("\"selected_remaining_at_failure_us\":null"));
    value["selected_remaining_at_failure_us"] = serde_json::json!(0);
    let record = parse_history_record(&format!("[HISTORY_MEASUREMENT_V1 {value}]"), false).unwrap();
    assert!(record
        .line()
        .contains("\"selected_remaining_at_failure_us\":0"));
}

pub(super) fn host<T>(boundary: Boundary, operation: impl FnOnce() -> Result<T>) -> Result<T> {
    #[cfg(feature = "synthetic-born-joined-qualification")]
    crate::host::synthetic_roster_timing_v1::event(boundary.label(), true, false);
    emit(boundary, Outcome::Begin);
    let result = operation();
    #[cfg(feature = "synthetic-born-joined-qualification")]
    crate::host::synthetic_roster_timing_v1::event(boundary.label(), false, result.is_err());
    emit(
        boundary,
        result
            .as_ref()
            .map_or_else(host_error, |_| Outcome::Complete),
    );
    result
}
fn host_error(error: &Error) -> Outcome {
    match error {
        Error::Platform => Outcome::HostPlatform,
        Error::Terminal => Outcome::HostTerminal,
        Error::Permission => Outcome::HostPermission,
        Error::Locked => Outcome::HostLocked,
        Error::Invalid => Outcome::HostInvalid,
        Error::Authentication => Outcome::HostAuthentication,
        Error::Storage => Outcome::HostStorage,
        Error::Quarantined => Outcome::HostQuarantined,
        Error::Unsupported => Outcome::HostUnsupported,
        Error::Receipt(_) => Outcome::HostReceipt,
        Error::RecoverySemantic(_) => Outcome::HostRecoverySemantic,
        Error::RecoveryBackupUnsupported => Outcome::HostRecoveryBackupUnsupported,
        Error::RecoveryFinancialUnsupported => Outcome::HostRecoveryFinancialUnsupported,
        Error::CompleteOriginRecoveryUnavailable => Outcome::HostCompleteOriginRecoveryUnavailable,
        Error::HistoricalExportIncomplete => Outcome::HostHistoricalExportIncomplete,
        Error::GenerationArchiveIncomplete => Outcome::HostGenerationArchiveIncomplete,
    }
}
#[cfg(feature = "synthetic-born-joined-qualification")]
pub(super) fn signer_error(error: &wholepact_signer::Error) -> Outcome {
    use wholepact_signer::Error as E;
    match error {
        E::Unavailable => Outcome::SignerUnavailable,
        E::PeerLifetimeUnavailable => Outcome::SignerPeerLifetimeUnavailable,
        E::Io(_) => Outcome::SignerIo,
        E::Authentication => Outcome::SignerAuthentication,
        E::InvalidData => Outcome::SignerInvalidData,
        E::Crypto => Outcome::SignerCrypto,
        E::Locked => Outcome::SignerLocked,
        E::BackupRequired => Outcome::SignerBackupRequired,
        E::RecoveryRequired => Outcome::SignerRecoveryRequired,
        E::AlreadyOpen => Outcome::SignerAlreadyOpen,
        E::ReviewMismatch => Outcome::SignerReviewMismatch,
        E::Verification => Outcome::SignerVerification,
        E::Uncertain => Outcome::SignerUncertain,
        E::ConsentJournal(_) => Outcome::SignerConsentJournal,
        E::Store(_) => Outcome::SignerStore,
    }
}
#[cfg(feature = "synthetic-born-joined-qualification")]
pub(super) fn authority_error(error: &wholepact_authority::AuthorityError) -> Outcome {
    use wholepact_authority::AuthorityError as E;
    match error {
        E::InvalidBinding => Outcome::AuthorityInvalidBinding,
        E::Permission => Outcome::AuthorityPermission,
        E::StaleHead => Outcome::AuthorityStaleHead,
        E::Conflict => Outcome::AuthorityConflict,
        E::Inactive => Outcome::AuthorityInactive,
        E::RecoveryRequired => Outcome::AuthorityRecoveryRequired,
        E::Expired => Outcome::AuthorityExpired,
        E::PolicyDenied => Outcome::AuthorityPolicyDenied,
        E::BudgetExceeded => Outcome::AuthorityBudgetExceeded,
        E::InputReserved => Outcome::AuthorityInputReserved,
        E::ObligationReserved => Outcome::AuthorityObligationReserved,
        E::Limit => Outcome::AuthorityLimit,
        E::Storage => Outcome::AuthorityStorage,
        E::CorruptHistory => Outcome::AuthorityCorruptHistory,
        E::PermanentStopUnavailable => Outcome::AuthorityPermanentStopUnavailable,
        E::OfflineHistoryUnsupported => Outcome::AuthorityOfflineHistoryUnsupported,
        E::ConstructionHistoryUnsupported => Outcome::AuthorityConstructionHistoryUnsupported,
        E::UnsupportedVersion => Outcome::AuthorityUnsupportedVersion,
        E::Authentication => Outcome::AuthorityAuthentication,
        E::Uncertain => Outcome::AuthorityUncertain,
        E::ResolutionUnavailable => Outcome::AuthorityResolutionUnavailable,
        E::SessionRequired => Outcome::AuthoritySessionRequired,
        E::SessionPending => Outcome::AuthoritySessionPending,
    }
}

/// Called only with locally generated labels. Parse again before disclosing:
/// even a spoofed marker cannot cause arbitrary transcript content to escape.
pub(super) fn summary(transcript: &[u8]) -> String {
    let mut output = std::collections::VecDeque::new();
    for line in transcript.split(|byte| *byte == b'\n') {
        let Ok(line) = std::str::from_utf8(line) else {
            continue;
        };
        let line = line.trim_end_matches('\r');
        if let Some(inner) = line
            .strip_prefix("[JOINED_IO ")
            .and_then(|s| s.strip_suffix(']'))
        {
            let mut fields = inner.split(' ');
            let (Some(boundary), Some(kind), Some(errno), None) =
                (fields.next(), fields.next(), fields.next(), fields.next())
            else {
                continue;
            };
            let Some(boundary) = Boundary::parse(boundary) else {
                continue;
            };
            if !matches!(
                kind,
                "NotFound"
                    | "PermissionDenied"
                    | "AlreadyExists"
                    | "InvalidInput"
                    | "InvalidData"
                    | "AddrInUse"
                    | "AddrNotAvailable"
                    | "WouldBlock"
                    | "TimedOut"
                    | "Interrupted"
                    | "Unsupported"
                    | "Other"
            ) || (errno != "none" && !errno.parse::<i32>().is_ok_and(|n| n.to_string() == errno))
            {
                continue;
            }
            if output.len() == 64 {
                output.pop_front();
            }
            output.push_back(format!("{}:IoKind={kind}:errno={errno}", boundary.label()));
            continue;
        }
        let Some(inner) = line
            .strip_prefix("[JOINED_DIAGNOSTIC ")
            .and_then(|s| s.strip_suffix(']'))
        else {
            continue;
        };
        let Some((boundary, outcome)) = inner.split_once(' ') else {
            continue;
        };
        let (Some(boundary), Some(outcome)) = (Boundary::parse(boundary), Outcome::parse(outcome))
        else {
            continue;
        };
        if output.len() == 64 {
            output.pop_front();
        }
        output.push_back(format!("{}:{}", boundary.label(), outcome.label()));
    }
    if output.is_empty() {
        "none".into()
    } else {
        output.into_iter().collect::<Vec<_>>().join(",")
    }
}

#[test]
fn private_transcript_diagnostic_projection_is_closed_and_bounded() {
    let transcript = b"private-path-and-key-material\n[JOINED_DIAGNOSTIC AgreementNative HostInvalid]\r\n[JOINED_DIAGNOSTIC AgreementNative HostInvalid extra-private-data]\n[JOINED_DIAGNOSTIC unknown HostInvalid]\n";
    assert_eq!(summary(transcript), "AgreementNative:HostInvalid");
    assert_eq!(
        summary(b"\xffprivate\n[JOINED_DIAGNOSTIC Bootstrap Begin] secret"),
        "none"
    );
    assert_eq!(
        summary(b"[JOINED_DIAGNOSTIC SingleWorkPrepareReentry Begin]\n[JOINED_DIAGNOSTIC SingleWorkPrepareReentry SignerAuthentication]\n[JOINED_DIAGNOSTIC SingleWorkAdoptOutput Complete]\n[JOINED_DIAGNOSTIC SingleWorkUnknown SignerAuthentication]\n[JOINED_DIAGNOSTIC SingleWorkPrepareReentry SignerAuthentication private-data]"),
        "SingleWorkPrepareReentry:Begin,SingleWorkPrepareReentry:SignerAuthentication,SingleWorkAdoptOutput:Complete"
    );
    assert_eq!(summary(b"[JOINED_DIAGNOSTIC RetainedMaterial HostReceipt]\n[JOINED_DIAGNOSTIC ContinuedObservation HostAuthentication]\n[JOINED_DIAGNOSTIC RetainedUnknown HostReceipt]\n[JOINED_DIAGNOSTIC RetainedMaterial HostReceipt private-data]"), "RetainedMaterial:HostReceipt,ContinuedObservation:HostAuthentication");
    let long = "[JOINED_DIAGNOSTIC Bootstrap Begin]\n".repeat(100);
    assert_eq!(summary(long.as_bytes()).split(',').count(), 64);
}

#[test]
fn io_diagnostics_accept_only_closed_kind_and_canonical_errno() {
    assert_eq!(summary(b"[JOINED_IO SingleIpcBind InvalidInput none]\n[JOINED_IO SingleDirectoryOpen PermissionDenied 1]"), "SingleIpcBind:IoKind=InvalidInput:errno=none,SingleDirectoryOpen:IoKind=PermissionDenied:errno=1");
    for line in [
        "[JOINED_IO private-path InvalidInput none]",
        "[JOINED_IO SingleIpcBind /private/path 1]",
        "[JOINED_IO SingleIpcBind InvalidInput 1/private]",
        "[JOINED_IO SingleIpcBind InvalidInput +1]",
        "[JOINED_IO SingleIpcBind InvalidInput 2147483648]",
        "[JOINED_IO SingleIpcBind InvalidInput 1 extra]",
    ] {
        assert_eq!(summary(line.as_bytes()), "none");
    }
}

#[test]
#[cfg(feature = "synthetic-born-joined-qualification")]
fn authority_error_projection_preserves_only_closed_variants() {
    use wholepact_authority::AuthorityError as E;
    let cases = [
        (E::InvalidBinding, "AuthorityInvalidBinding"),
        (E::Permission, "AuthorityPermission"),
        (E::StaleHead, "AuthorityStaleHead"),
        (E::Conflict, "AuthorityConflict"),
        (E::Inactive, "AuthorityInactive"),
        (E::RecoveryRequired, "AuthorityRecoveryRequired"),
        (E::Expired, "AuthorityExpired"),
        (E::PolicyDenied, "AuthorityPolicyDenied"),
        (E::BudgetExceeded, "AuthorityBudgetExceeded"),
        (E::InputReserved, "AuthorityInputReserved"),
        (E::ObligationReserved, "AuthorityObligationReserved"),
        (E::Limit, "AuthorityLimit"),
        (E::Storage, "AuthorityStorage"),
        (E::CorruptHistory, "AuthorityCorruptHistory"),
        (
            E::PermanentStopUnavailable,
            "AuthorityPermanentStopUnavailable",
        ),
        (
            E::OfflineHistoryUnsupported,
            "AuthorityOfflineHistoryUnsupported",
        ),
        (
            E::ConstructionHistoryUnsupported,
            "AuthorityConstructionHistoryUnsupported",
        ),
        (E::UnsupportedVersion, "AuthorityUnsupportedVersion"),
        (E::Authentication, "AuthorityAuthentication"),
        (E::Uncertain, "AuthorityUncertain"),
        (E::ResolutionUnavailable, "AuthorityResolutionUnavailable"),
        (E::SessionRequired, "AuthoritySessionRequired"),
        (E::SessionPending, "AuthoritySessionPending"),
    ];
    for (error, expected) in cases {
        let actual = authority_error(&error).label();
        assert_eq!(actual, expected);
        let valid = format!("[JOINED_DIAGNOSTIC ObservedPlanWitnessOrigin {actual}]");
        assert_eq!(
            summary(valid.as_bytes()),
            format!("ObservedPlanWitnessOrigin:{expected}")
        );
        let invalid =
            format!("[JOINED_DIAGNOSTIC ObservedPlanWitnessOrigin {actual} private-data]");
        assert_eq!(summary(invalid.as_bytes()), "none");
    }
    assert_eq!(
        summary(b"[JOINED_DIAGNOSTIC WitnessPlanInput AuthorityInputOverBound]"),
        "WitnessPlanInput:AuthorityInputOverBound"
    );
    assert_eq!(
        summary(b"[JOINED_DIAGNOSTIC WitnessPlanInput 262145]"),
        "none"
    );
    assert_eq!(
        summary(b"[JOINED_DIAGNOSTIC WitnessPlanWorkerPrepare AuthorityUnsupportedVersion]"),
        "WitnessPlanWorkerPrepare:AuthorityUnsupportedVersion"
    );
}

#[cfg(all(test, feature = "synthetic-born-joined-qualification"))]
fn admission_test_rows() -> [serde_json::Value; 3] {
    [
        ADMISSION_MEASUREMENT_TEST_JSON,
        SIGNER_ADMISSION_TEST_JSON,
        WITNESS_ADMISSION_TEST_JSON,
    ]
    .map(|text| serde_json::from_str(text).unwrap())
}

#[test]
#[cfg(feature = "synthetic-born-joined-qualification")]
fn admission_parser_requires_every_exact_field_and_rejects_duplicates() {
    fn visit(value: &serde_json::Value, path: &mut Vec<String>, paths: &mut Vec<Vec<String>>) {
        if let Some(object) = value.as_object() {
            paths.push(path.clone());
            for (key, child) in object {
                path.push(key.clone());
                visit(child, path, paths);
                path.pop();
            }
        }
    }
    fn at<'a>(value: &'a mut serde_json::Value, path: &[String]) -> &'a mut serde_json::Value {
        let mut found = value;
        for key in path {
            found = found.get_mut(key).unwrap();
        }
        found
    }
    for (slot, original) in admission_test_rows().into_iter().enumerate() {
        let valid = format!("{}{original}]", ADMISSION_PREFIXES[slot]);
        assert!(parse_admission_record(&valid, slot).is_some());
        let mut paths = Vec::new();
        visit(&original, &mut Vec::new(), &mut paths);
        for path in paths {
            let mut object = original.clone();
            let keys = at(&mut object, &path)
                .as_object()
                .unwrap()
                .keys()
                .cloned()
                .collect::<Vec<_>>();
            for key in keys {
                let mut missing = original.clone();
                at(&mut missing, &path)
                    .as_object_mut()
                    .unwrap()
                    .remove(&key);
                assert!(parse_admission_record(
                    &format!("{}{missing}]", ADMISSION_PREFIXES[slot]),
                    slot
                )
                .is_none());
                let mut confused = original.clone();
                at(&mut confused, &path)[&key] = serde_json::json!(["private"]);
                assert!(parse_admission_record(
                    &format!("{}{confused}]", ADMISSION_PREFIXES[slot]),
                    slot
                )
                .is_none());
            }
            let mut unknown = original.clone();
            at(&mut unknown, &path)["private"] = serde_json::json!("payload");
            assert!(parse_admission_record(
                &format!("{}{unknown}]", ADMISSION_PREFIXES[slot]),
                slot
            )
            .is_none());
            let text = original.to_string();
            let key = at(&mut object, &path)
                .as_object()
                .unwrap()
                .keys()
                .next()
                .unwrap()
                .clone();
            let duplicate = text.replacen(
                &format!("\"{key}\":"),
                &format!("\"{key}\":null,\"{key}\":"),
                1,
            );
            assert!(parse_admission_record(
                &format!("{}{duplicate}]", ADMISSION_PREFIXES[slot]),
                slot
            )
            .is_none());
        }
    }
}

#[test]
#[cfg(feature = "synthetic-born-joined-qualification")]
fn admission_parser_preserves_unavailable_zero_and_commit_uncertainty() {
    let mut rows = admission_test_rows();
    rows[0]["selected_remaining_at_failure_us"] = serde_json::Value::Null;
    rows[1]["measurement"]["callback_custody_us"] = serde_json::Value::Null;
    rows[2]["snapshot_recorded"] = serde_json::Value::Null;
    for commit in ["NotObserved", "Entered", "ReturnedOk", "ReturnedErr"] {
        rows[2]["commit"] = serde_json::json!(commit);
        let record = parse_admission_record(
            &format!("{}{row}]", ADMISSION_PREFIXES[2], row = rows[2]),
            2,
        )
        .unwrap();
        assert!(record.line.contains(&format!("\"commit\":\"{commit}\"")));
        assert!(record.line.contains("\"snapshot_recorded\":null"));
    }
    for (slot, row) in rows.iter().enumerate() {
        assert!(
            parse_admission_record(&format!("{}{row}]", ADMISSION_PREFIXES[slot]), slot).is_some()
        );
    }
    rows[0]["selected_remaining_at_failure_us"] = serde_json::json!(0);
    rows[1]["measurement"]["callback_custody_us"] = serde_json::json!(0);
    rows[2]["cost"]["commit"]["elapsed_us"] = serde_json::json!(0);
    for (slot, row) in rows.iter().enumerate() {
        assert!(
            parse_admission_record(&format!("{}{row}]", ADMISSION_PREFIXES[slot]), slot).is_some()
        );
    }
    let mut history: serde_json::Value =
        serde_json::from_str(HISTORY_MEASUREMENT_TEST_JSON).unwrap();
    history["phase"] = serde_json::json!("Admission");
    assert!(parse_history_record(&format!("[HISTORY_MEASUREMENT_V1 {history}]"), false).is_none());
    for phase in ["Snapshot", "Page"] {
        rows[0]["phase"] = serde_json::json!(phase);
        assert!(parse_admission_record(
            &format!("{}{row}]", ADMISSION_PREFIXES[0], row = rows[0]),
            0
        )
        .is_none());
    }
}

#[test]
#[cfg(feature = "synthetic-born-joined-qualification")]
fn admission_parser_rejects_out_of_bounds_and_type_confused_scalars() {
    for (slot, mut row) in admission_test_rows().into_iter().enumerate() {
        for value in [
            serde_json::json!(true),
            serde_json::json!(0),
            serde_json::json!(2),
            serde_json::json!(1.0),
        ] {
            row["version"] = value;
            assert!(
                parse_admission_record(&format!("{}{row}]", ADMISSION_PREFIXES[slot]), slot)
                    .is_none()
            );
        }
        assert!(parse_admission_record(
            &format!("{}{}]", ADMISSION_PREFIXES[slot], " ".repeat(4097)),
            slot
        )
        .is_none());
    }
    for value in [
        serde_json::json!(-1),
        serde_json::json!(true),
        serde_json::json!(1.0),
        serde_json::json!(600_000_001u64),
    ] {
        let mut rows = admission_test_rows();
        rows[0]["operation_elapsed_us"] = value.clone();
        rows[1]["measurement"]["request_validation_us"] = value.clone();
        rows[2]["cost"]["commit"]["elapsed_us"] = value;
        for (slot, row) in rows.iter().enumerate() {
            assert!(
                parse_admission_record(&format!("{}{row}]", ADMISSION_PREFIXES[slot]), slot)
                    .is_none()
            );
        }
    }
    let mut rows = admission_test_rows();
    rows[0]["operation_cost"]["callback_calls"] = serde_json::json!(1_000_001);
    rows[1]["measurement"]["request_validation_calls"] = serde_json::json!(1_000_001);
    rows[2]["cost"]["commit"]["calls"] = serde_json::json!(1_000_001);
    for (slot, row) in rows.iter().enumerate() {
        assert!(
            parse_admission_record(&format!("{}{row}]", ADMISSION_PREFIXES[slot]), slot).is_none()
        );
    }
}

#[test]
#[cfg(feature = "synthetic-born-joined-qualification")]
fn admission_capture_slots_are_independent_sticky_and_bounded() {
    let lines = admission_test_rows()
        .into_iter()
        .enumerate()
        .map(|(slot, row)| format!("{}{row}]", ADMISSION_PREFIXES[slot]))
        .collect::<Vec<_>>();
    let mut capture = AdmissionDiagnosticCapture::default();
    capture.capture_line(&format!("private {}", lines[0]), 16384);
    assert!(capture.public_lines().is_empty());
    for line in &lines {
        capture.capture_line(line, 16384);
    }
    assert_eq!(capture.public_lines().len(), 3);
    assert!(capture.retained_bytes() < 3 * (4096 + 32));
    capture.capture_line(&lines[1], 16384);
    assert_eq!(capture.public_lines()[1], ADMISSION_INVALID[1]);
    assert_eq!(capture.public_lines()[0], lines[0]);
    assert_eq!(capture.public_lines()[2], lines[2]);
    capture.capture_line(&lines[1], 16384);
    assert_eq!(capture.public_lines()[1], ADMISSION_INVALID[1]);
    capture.discard_for_budget();
    assert_eq!(capture.retained_bytes(), 0);
    for line in &lines {
        capture.capture_line(line, 16384);
    }
    assert_eq!(capture.public_lines(), ADMISSION_INVALID);
    let mut capture = AdmissionDiagnosticCapture::default();
    capture.capture_line(&lines[0], 1);
    capture.capture_line(&lines[0], 16384);
    assert_eq!(capture.public_lines(), vec![ADMISSION_INVALID[0]]);
    capture.capture_line(ADMISSION_INVALID[2], 16384);
    capture.capture_line(&lines[2], 16384);
    assert_eq!(capture.public_lines()[1], ADMISSION_INVALID[2]);
}

// This failure-only schema is independent of unchanged History/Admission records.
#[cfg(feature = "synthetic-born-joined-qualification")]
mod durable_flow_projection {
    use super::{
        PublicHistoryCost, admission_io_kind_label, history_check_site_label,
        history_checkpoint_label, history_selected_limit_label, required_history_nullable,
    };
    use wholepact_authority::transport::history_diagnostics_v1::{
        CheckedHistoryCostV1, CheckedHistoryMeasurementV1, CheckedHistoryPhaseV1,
    };
    use wholepact_signer::native_ui::synthetic_born_joined_qualification::{
        DurableFlowAuthorityCodeV1, DurableFlowCallOutcomeV1, DurableFlowCallbackStageV1,
        DurableFlowDiagnosticV1, DurableFlowErrorCodeV1, DurableFlowErrorDomainV1,
        DurableFlowErrorV1, DurableFlowJobPurposeV1, DurableFlowNestedCodeV1,
        DurableFlowOperationV1, DurableFlowPresentationV1, DurableFlowReceiveV1,
        DurableFlowResultV1, DurableFlowStageV1, DurableFlowTransportFailureV1,
        DurableFlowTransportPurposeV1, DurableFlowTransportStageV1,
    };
    const PRIVATE_PREFIX: &str = "[DURABLE_FLOW_V1 ";
    const PUBLIC_PREFIX: &str = "CI_SYNTHETIC_DURABLE_FLOW ";
    const INVALID: &str = "CI_SYNTHETIC_DURABLE_FLOW invalid=true details_withheld=true";
    const MAX_PAYLOAD: usize = 4096;
    macro_rules! flow_labels {
        ($function:ident, $inventory:ident, $ty:ident, {$($variant:ident => $label:literal),+ $(,)?}) => {
            fn $function(value: $ty) -> &'static str {
                match value { $($ty::$variant => $label),+ }
            }
            #[cfg(test)]
            const $inventory: &[($ty, &str)] = &[$(($ty::$variant, $label)),+];
        }
    }
    flow_labels!(flow_operation_label, FLOW_OPERATION_LABELS, DurableFlowOperationV1, {
        WriterReconcile => "WriterReconcile",
        FinancialImport => "FinancialImport",
        InitialSign => "InitialSign",
        RetainedRetry => "RetainedRetry",
        ResultService => "ResultService",
    });
    flow_labels!(flow_stage_label, FLOW_STAGE_LABELS, DurableFlowStageV1, {
        FixtureState => "FixtureState",
        AcquirePrepare => "AcquirePrepare",
        AcquireNative => "AcquireNative",
        AcquireCall => "AcquireCall",
        ActivationPrepare => "ActivationPrepare",
        ActivationNative => "ActivationNative",
        ActivationCall => "ActivationCall",
        ActiveVerification => "ActiveVerification",
        ReconcilePrepare => "ReconcilePrepare",
        ReconcileNative => "ReconcileNative",
        ReconcileCall => "ReconcileCall",
        Invalidate => "Invalidate",
        ImportReceive => "ImportReceive",
        ImportPairing => "ImportPairing",
        ImportSource => "ImportSource",
        WalletSync => "WalletSync",
        WalletSource => "WalletSource",
        WitnessHead => "WitnessHead",
        SpendStage => "SpendStage",
        DisclosureDecision => "DisclosureDecision",
        SpendDecision => "SpendDecision",
        SigningLaunch => "SigningLaunch",
        AuthorizationSource => "AuthorizationSource",
        Release => "Release",
        RequestRetain => "RequestRetain",
        Reserve => "Reserve",
        PermitRetain => "PermitRetain",
        WalletGuard => "WalletGuard",
        KeyUse => "KeyUse",
        Derive => "Derive",
        Sign => "Sign",
        VerifySigned => "VerifySigned",
        ResultRetain => "ResultRetain",
        RetainedLookup => "RetainedLookup",
        RetryInvariant => "RetryInvariant",
        Completion => "Completion",
        ResultService => "ResultService",
        Close => "Close",
    });
    flow_labels!(flow_error_domain_label, FLOW_ERROR_DOMAIN_LABELS, DurableFlowErrorDomainV1, {
        Signer => "Signer",
        Bridge => "Bridge",
        Authority => "Authority",
        Journal => "Journal",
        WalletKeyUse => "WalletKeyUse",
        Store => "Store",
    });
    flow_labels!(flow_job_purpose_label, FLOW_JOB_PURPOSE_LABELS, DurableFlowJobPurposeV1, {
        AcquirePrepare => "AcquirePrepare",
        Acquire => "Acquire",
        ActivationPrepare => "ActivationPrepare",
        Activate => "Activate",
        ReconcilePrepare => "ReconcilePrepare",
        Reconcile => "Reconcile",
        Import => "Import",
        WalletReview => "WalletReview",
        Sign => "Sign",
        ResultService => "ResultService",
    });
    flow_labels!(flow_result_label, FLOW_RESULT_LABELS, DurableFlowResultV1, {
        NotObserved => "NotObserved",
        ReturnedOk => "ReturnedOk",
        ReturnedErr => "ReturnedErr",
    });
    flow_labels!(flow_receive_label, FLOW_RECEIVE_LABELS, DurableFlowReceiveV1, {
        NotObserved => "NotObserved",
        Pending => "Pending",
        Received => "Received",
        Missing => "Missing",
        Disconnected => "Disconnected",
        Invalidated => "Invalidated",
    });
    flow_labels!(flow_presentation_label, FLOW_PRESENTATION_LABELS, DurableFlowPresentationV1, {
        NotObserved => "NotObserved",
        Accepted => "Accepted",
        Suppressed => "Suppressed",
    });
    flow_labels!(flow_call_outcome_label, FLOW_CALL_OUTCOME_LABELS, DurableFlowCallOutcomeV1, {
        NotObserved => "NotObserved",
        Entered => "Entered",
        ReturnedOk => "ReturnedOk",
        ReturnedErr => "ReturnedErr",
    });
    flow_labels!(flow_transport_purpose_label, FLOW_TRANSPORT_PURPOSE_LABELS, DurableFlowTransportPurposeV1, {
        Acquire => "Acquire",
        Activate => "Activate",
        Verify => "Verify",
        Reserve => "Reserve",
    });
    flow_labels!(flow_transport_stage_label, FLOW_TRANSPORT_STAGE_LABELS, DurableFlowTransportStageV1, {
        RequestValidation => "RequestValidation",
        Binding => "Binding",
        Session => "Session",
        CallerDeadline => "CallerDeadline",
        ExchangeDeadline => "ExchangeDeadline",
        SourceCallback => "SourceCallback",
        Connect => "Connect",
        Handshake => "Handshake",
        PeerBinding => "PeerBinding",
        RequestBuild => "RequestBuild",
        RequestWrite => "RequestWrite",
        ResponseRead => "ResponseRead",
        Response => "Response",
        SnapshotValidation => "SnapshotValidation",
        ReceiptValidation => "ReceiptValidation",
        CommittedHeadValidation => "CommittedHeadValidation",
        FinalValidation => "FinalValidation",
        Bounds => "Bounds",
    });
    flow_labels!(flow_authority_code_label, FLOW_AUTHORITY_CODE_LABELS, DurableFlowAuthorityCodeV1, {
        InvalidBinding => "InvalidBinding",
        Permission => "Permission",
        StaleHead => "StaleHead",
        Conflict => "Conflict",
        Inactive => "Inactive",
        RecoveryRequired => "RecoveryRequired",
        Expired => "Expired",
        PolicyDenied => "PolicyDenied",
        BudgetExceeded => "BudgetExceeded",
        InputReserved => "InputReserved",
        ObligationReserved => "ObligationReserved",
        Limit => "Limit",
        Storage => "Storage",
        CorruptHistory => "CorruptHistory",
        PermanentStopUnavailable => "PermanentStopUnavailable",
        OfflineHistoryUnsupported => "OfflineHistoryUnsupported",
        ConstructionHistoryUnsupported => "ConstructionHistoryUnsupported",
        UnsupportedVersion => "UnsupportedVersion",
        Authentication => "Authentication",
        Uncertain => "Uncertain",
        ResolutionUnavailable => "ResolutionUnavailable",
        SessionRequired => "SessionRequired",
        SessionPending => "SessionPending",
    });
    flow_labels!(flow_callback_stage_label, FLOW_CALLBACK_STAGE_LABELS, DurableFlowCallbackStageV1, {
        WorkspaceCurrent => "WorkspaceCurrent",
        CallerCurrent => "CallerCurrent",
    });
    flow_labels!(flow_error_code_label, FLOW_ERROR_CODE_LABELS, DurableFlowErrorCodeV1, {
        SignerUnavailable => "Unavailable",
        SignerPeerLifetimeUnavailable => "PeerLifetimeUnavailable",
        SignerIo => "Io",
        SignerAuthentication => "Authentication",
        SignerInvalidData => "InvalidData",
        SignerCrypto => "Crypto",
        SignerLocked => "Locked",
        SignerBackupRequired => "BackupRequired",
        SignerRecoveryRequired => "RecoveryRequired",
        SignerAlreadyOpen => "AlreadyOpen",
        SignerReviewMismatch => "ReviewMismatch",
        SignerVerification => "Verification",
        SignerUncertain => "Uncertain",
        SignerConsentJournal => "ConsentJournal",
        SignerStore => "Store",
        BridgeBinding => "Binding",
        BridgeConflict => "Conflict",
        BridgeMissing => "Missing",
        BridgeUncertain => "Uncertain",
        BridgeLimit => "Limit",
        BridgePermission => "Permission",
        BridgeRecoveryRequired => "RecoveryRequired",
        BridgeCompleteOriginRecoveryUnavailable => "CompleteOriginRecoveryUnavailable",
        BridgeVerification => "Verification",
        BridgeSignerOriginUnavailable => "SignerOriginUnavailable",
        BridgeJournal => "Journal",
        BridgeAuthority => "Authority",
        BridgeWallet => "Wallet",
        BridgeIpc => "Ipc",
        AuthorityInvalidBinding => "InvalidBinding",
        AuthorityPermission => "Permission",
        AuthorityStaleHead => "StaleHead",
        AuthorityConflict => "Conflict",
        AuthorityInactive => "Inactive",
        AuthorityRecoveryRequired => "RecoveryRequired",
        AuthorityExpired => "Expired",
        AuthorityPolicyDenied => "PolicyDenied",
        AuthorityBudgetExceeded => "BudgetExceeded",
        AuthorityInputReserved => "InputReserved",
        AuthorityObligationReserved => "ObligationReserved",
        AuthorityLimit => "Limit",
        AuthorityStorage => "Storage",
        AuthorityCorruptHistory => "CorruptHistory",
        AuthorityPermanentStopUnavailable => "PermanentStopUnavailable",
        AuthorityOfflineHistoryUnsupported => "OfflineHistoryUnsupported",
        AuthorityConstructionHistoryUnsupported => "ConstructionHistoryUnsupported",
        AuthorityUnsupportedVersion => "UnsupportedVersion",
        AuthorityAuthentication => "Authentication",
        AuthorityUncertain => "Uncertain",
        AuthorityResolutionUnavailable => "ResolutionUnavailable",
        AuthoritySessionRequired => "SessionRequired",
        AuthoritySessionPending => "SessionPending",
        JournalStorage => "Storage",
        JournalDatabase => "Database",
        JournalPermission => "Permission",
        JournalExpired => "Expired",
        JournalRecoveryRequired => "RecoveryRequired",
        JournalUnsupportedSchema => "UnsupportedSchema",
        JournalOfflineHistoryUnsupported => "OfflineHistoryUnsupported",
        JournalNamedRecipientHistoryUnsupported => "NamedRecipientHistoryUnsupported",
        JournalConstructionHistoryUnsupported => "ConstructionHistoryUnsupported",
        JournalInvalidBinding => "InvalidBinding",
        JournalConflict => "Conflict",
        JournalNotFound => "NotFound",
        JournalLiveAuthorization => "LiveAuthorization",
        JournalInputReserved => "InputReserved",
        JournalBudgetExceeded => "BudgetExceeded",
        JournalLimit => "Limit",
        WalletKeyUsePermission => "Permission",
        WalletKeyUsePolicy => "Policy",
        WalletKeyUseSelectionExpired => "SelectionExpired",
        WalletKeyUseStorage => "Storage",
        WalletKeyUseRecoveryRequired => "RecoveryRequired",
        WalletKeyUseStateChanged => "StateChanged",
        WalletKeyUseExpiry => "Expiry",
        WalletKeyUseSync => "Sync",
        StoreStorageSecurity => "StorageSecurity",
        StoreDatabase => "Database",
        StoreEncoding => "Encoding",
        StorePoisoned => "Poisoned",
        StoreIdempotencyConflict => "IdempotencyConflict",
        StoreRevisionConflict => "RevisionConflict",
        StoreNotFound => "NotFound",
        StoreAlreadyExists => "AlreadyExists",
        StoreInvalidInput => "InvalidInput",
        StoreUnsupportedSchema => "UnsupportedSchema",
        StoreRecoveryRequired => "RecoveryRequired",
        StoreWriterEpochMismatch => "WriterEpochMismatch",
        StoreLiveAuthorizationExists => "LiveAuthorizationExists",
        StoreInputReserved => "InputReserved",
        StoreResourceExhausted => "ResourceExhausted",
        StoreBudgetExceeded => "BudgetExceeded",
        StoreInvalidTransition => "InvalidTransition",
        StoreFile => "File",
    });
    flow_labels!(flow_nested_code_label, FLOW_NESTED_CODE_LABELS, DurableFlowNestedCodeV1, {
        JournalStorage => "JournalStorage",
        JournalDatabase => "JournalDatabase",
        JournalPermission => "JournalPermission",
        JournalExpired => "JournalExpired",
        JournalRecoveryRequired => "JournalRecoveryRequired",
        JournalUnsupportedSchema => "JournalUnsupportedSchema",
        JournalOfflineHistoryUnsupported => "JournalOfflineHistoryUnsupported",
        JournalNamedRecipientHistoryUnsupported => "JournalNamedRecipientHistoryUnsupported",
        JournalConstructionHistoryUnsupported => "JournalConstructionHistoryUnsupported",
        JournalInvalidBinding => "JournalInvalidBinding",
        JournalConflict => "JournalConflict",
        JournalNotFound => "JournalNotFound",
        JournalLiveAuthorization => "JournalLiveAuthorization",
        JournalInputReserved => "JournalInputReserved",
        JournalBudgetExceeded => "JournalBudgetExceeded",
        JournalLimit => "JournalLimit",
        StoreStorageSecurity => "StoreStorageSecurity",
        StoreDatabase => "StoreDatabase",
        StoreEncoding => "StoreEncoding",
        StorePoisoned => "StorePoisoned",
        StoreIdempotencyConflict => "StoreIdempotencyConflict",
        StoreRevisionConflict => "StoreRevisionConflict",
        StoreNotFound => "StoreNotFound",
        StoreAlreadyExists => "StoreAlreadyExists",
        StoreInvalidInput => "StoreInvalidInput",
        StoreUnsupportedSchema => "StoreUnsupportedSchema",
        StoreRecoveryRequired => "StoreRecoveryRequired",
        StoreWriterEpochMismatch => "StoreWriterEpochMismatch",
        StoreLiveAuthorizationExists => "StoreLiveAuthorizationExists",
        StoreInputReserved => "StoreInputReserved",
        StoreResourceExhausted => "StoreResourceExhausted",
        StoreBudgetExceeded => "StoreBudgetExceeded",
        StoreInvalidTransition => "StoreInvalidTransition",
        StoreFile => "StoreFile",
        AuthorityInvalidBinding => "AuthorityInvalidBinding",
        AuthorityPermission => "AuthorityPermission",
        AuthorityStaleHead => "AuthorityStaleHead",
        AuthorityConflict => "AuthorityConflict",
        AuthorityInactive => "AuthorityInactive",
        AuthorityRecoveryRequired => "AuthorityRecoveryRequired",
        AuthorityExpired => "AuthorityExpired",
        AuthorityPolicyDenied => "AuthorityPolicyDenied",
        AuthorityBudgetExceeded => "AuthorityBudgetExceeded",
        AuthorityInputReserved => "AuthorityInputReserved",
        AuthorityObligationReserved => "AuthorityObligationReserved",
        AuthorityLimit => "AuthorityLimit",
        AuthorityStorage => "AuthorityStorage",
        AuthorityCorruptHistory => "AuthorityCorruptHistory",
        AuthorityPermanentStopUnavailable => "AuthorityPermanentStopUnavailable",
        AuthorityOfflineHistoryUnsupported => "AuthorityOfflineHistoryUnsupported",
        AuthorityConstructionHistoryUnsupported => "AuthorityConstructionHistoryUnsupported",
        AuthorityUnsupportedVersion => "AuthorityUnsupportedVersion",
        AuthorityAuthentication => "AuthorityAuthentication",
        AuthorityUncertain => "AuthorityUncertain",
        AuthorityResolutionUnavailable => "AuthorityResolutionUnavailable",
        AuthoritySessionRequired => "AuthoritySessionRequired",
        AuthoritySessionPending => "AuthoritySessionPending",
        WalletKeyUsePermission => "WalletKeyUsePermission",
        WalletKeyUsePolicy => "WalletKeyUsePolicy",
        WalletKeyUseSelectionExpired => "WalletKeyUseSelectionExpired",
        WalletKeyUseStorage => "WalletKeyUseStorage",
        WalletKeyUseRecoveryRequired => "WalletKeyUseRecoveryRequired",
        WalletKeyUseStateChanged => "WalletKeyUseStateChanged",
        WalletKeyUseExpiry => "WalletKeyUseExpiry",
        WalletKeyUseSync => "WalletKeyUseSync",
        StorageSecurityUnsupportedPlatform => "StorageSecurityUnsupportedPlatform",
        StorageSecurityQuarantinedDatabase => "StorageSecurityQuarantinedDatabase",
        StorageSecurityRecoveredGeneration => "StorageSecurityRecoveredGeneration",
        StorageSecurityGenerationArchive => "StorageSecurityGenerationArchive",
        StorageSecurityUninitializedDatabase => "StorageSecurityUninitializedDatabase",
        StorageSecurityUnsafePath => "StorageSecurityUnsafePath",
        StorageSecurityAlreadyExists => "StorageSecurityAlreadyExists",
        StorageSecurityMissingDatabase => "StorageSecurityMissingDatabase",
        StorageSecurityPlaintextRefused => "StorageSecurityPlaintextRefused",
        StorageSecurityUnqualifiedRuntime => "StorageSecurityUnqualifiedRuntime",
        StorageSecurityAuthenticationFailed => "StorageSecurityAuthenticationFailed",
        StorageSecurityDatabase => "StorageSecurityDatabase",
        StorageSecurityIo => "StorageSecurityIo",
        StorageSecuritySnapshotLimit => "StorageSecuritySnapshotLimit",
        StorageSecuritySourceChanged => "StorageSecuritySourceChanged",
        SyncAccessDenied => "SyncAccessDenied",
        SyncInvalidRequest => "SyncInvalidRequest",
        SyncInterrupted => "SyncInterrupted",
        SyncReconciliationRequired => "SyncReconciliationRequired",
        SyncInvalidResponse => "SyncInvalidResponse",
        SyncResourceLimit => "SyncResourceLimit",
        SyncNoCurrentObservation => "SyncNoCurrentObservation",
        SyncWallet => "SyncWallet",
        SyncChain => "SyncChain",
    });
    const FLOW_OPERATION: &[&str] = &[
        "WriterReconcile",
        "FinancialImport",
        "InitialSign",
        "RetainedRetry",
        "ResultService",
    ];
    const FLOW_STAGE: &[&str] = &[
        "FixtureState",
        "AcquirePrepare",
        "AcquireNative",
        "AcquireCall",
        "ActivationPrepare",
        "ActivationNative",
        "ActivationCall",
        "ActiveVerification",
        "ReconcilePrepare",
        "ReconcileNative",
        "ReconcileCall",
        "Invalidate",
        "ImportReceive",
        "ImportPairing",
        "ImportSource",
        "WalletSync",
        "WalletSource",
        "WitnessHead",
        "SpendStage",
        "DisclosureDecision",
        "SpendDecision",
        "SigningLaunch",
        "AuthorizationSource",
        "Release",
        "RequestRetain",
        "Reserve",
        "PermitRetain",
        "WalletGuard",
        "KeyUse",
        "Derive",
        "Sign",
        "VerifySigned",
        "ResultRetain",
        "RetainedLookup",
        "RetryInvariant",
        "Completion",
        "ResultService",
        "Close",
    ];
    const FLOW_ERROR_DOMAIN: &[&str] = &[
        "Signer",
        "Bridge",
        "Authority",
        "Journal",
        "WalletKeyUse",
        "Store",
    ];
    const FLOW_JOB_PURPOSE: &[&str] = &[
        "AcquirePrepare",
        "Acquire",
        "ActivationPrepare",
        "Activate",
        "ReconcilePrepare",
        "Reconcile",
        "Import",
        "WalletReview",
        "Sign",
        "ResultService",
    ];
    const FLOW_RESULT: &[&str] = &["NotObserved", "ReturnedOk", "ReturnedErr"];
    const FLOW_RECEIVE: &[&str] = &[
        "NotObserved",
        "Pending",
        "Received",
        "Missing",
        "Disconnected",
        "Invalidated",
    ];
    const FLOW_PRESENTATION: &[&str] = &["NotObserved", "Accepted", "Suppressed"];
    const FLOW_CALL_OUTCOME: &[&str] = &["NotObserved", "Entered", "ReturnedOk", "ReturnedErr"];
    const FLOW_TRANSPORT_PURPOSE: &[&str] = &["Acquire", "Activate", "Verify", "Reserve"];
    const FLOW_TRANSPORT_STAGE: &[&str] = &[
        "RequestValidation",
        "Binding",
        "Session",
        "CallerDeadline",
        "ExchangeDeadline",
        "SourceCallback",
        "Connect",
        "Handshake",
        "PeerBinding",
        "RequestBuild",
        "RequestWrite",
        "ResponseRead",
        "Response",
        "SnapshotValidation",
        "ReceiptValidation",
        "CommittedHeadValidation",
        "FinalValidation",
        "Bounds",
    ];
    const FLOW_AUTHORITY_CODE: &[&str] = &[
        "InvalidBinding",
        "Permission",
        "StaleHead",
        "Conflict",
        "Inactive",
        "RecoveryRequired",
        "Expired",
        "PolicyDenied",
        "BudgetExceeded",
        "InputReserved",
        "ObligationReserved",
        "Limit",
        "Storage",
        "CorruptHistory",
        "PermanentStopUnavailable",
        "OfflineHistoryUnsupported",
        "ConstructionHistoryUnsupported",
        "UnsupportedVersion",
        "Authentication",
        "Uncertain",
        "ResolutionUnavailable",
        "SessionRequired",
        "SessionPending",
    ];
    const FLOW_CALLBACK_STAGE: &[&str] = &["WorkspaceCurrent", "CallerCurrent"];
    const FLOW_SIGNER_CODES: &[&str] = &[
        "Unavailable",
        "PeerLifetimeUnavailable",
        "Io",
        "Authentication",
        "InvalidData",
        "Crypto",
        "Locked",
        "BackupRequired",
        "RecoveryRequired",
        "AlreadyOpen",
        "ReviewMismatch",
        "Verification",
        "Uncertain",
        "ConsentJournal",
        "Store",
    ];
    const FLOW_BRIDGE_CODES: &[&str] = &[
        "Binding",
        "Conflict",
        "Missing",
        "Uncertain",
        "Limit",
        "Permission",
        "RecoveryRequired",
        "CompleteOriginRecoveryUnavailable",
        "Verification",
        "SignerOriginUnavailable",
        "Journal",
        "Authority",
        "Wallet",
        "Ipc",
    ];
    const FLOW_AUTHORITY_CODES: &[&str] = &[
        "InvalidBinding",
        "Permission",
        "StaleHead",
        "Conflict",
        "Inactive",
        "RecoveryRequired",
        "Expired",
        "PolicyDenied",
        "BudgetExceeded",
        "InputReserved",
        "ObligationReserved",
        "Limit",
        "Storage",
        "CorruptHistory",
        "PermanentStopUnavailable",
        "OfflineHistoryUnsupported",
        "ConstructionHistoryUnsupported",
        "UnsupportedVersion",
        "Authentication",
        "Uncertain",
        "ResolutionUnavailable",
        "SessionRequired",
        "SessionPending",
    ];
    const FLOW_JOURNAL_CODES: &[&str] = &[
        "Storage",
        "Database",
        "Permission",
        "Expired",
        "RecoveryRequired",
        "UnsupportedSchema",
        "OfflineHistoryUnsupported",
        "NamedRecipientHistoryUnsupported",
        "ConstructionHistoryUnsupported",
        "InvalidBinding",
        "Conflict",
        "NotFound",
        "LiveAuthorization",
        "InputReserved",
        "BudgetExceeded",
        "Limit",
    ];
    const FLOW_WALLET_KEY_USE_CODES: &[&str] = &[
        "Permission",
        "Policy",
        "SelectionExpired",
        "Storage",
        "RecoveryRequired",
        "StateChanged",
        "Expiry",
        "Sync",
    ];
    const FLOW_STORE_CODES: &[&str] = &[
        "StorageSecurity",
        "Database",
        "Encoding",
        "Poisoned",
        "IdempotencyConflict",
        "RevisionConflict",
        "NotFound",
        "AlreadyExists",
        "InvalidInput",
        "UnsupportedSchema",
        "RecoveryRequired",
        "WriterEpochMismatch",
        "LiveAuthorizationExists",
        "InputReserved",
        "ResourceExhausted",
        "BudgetExceeded",
        "InvalidTransition",
        "File",
    ];
    const FLOW_NESTED_JOURNAL: &[&str] = &[
        "JournalStorage",
        "JournalDatabase",
        "JournalPermission",
        "JournalExpired",
        "JournalRecoveryRequired",
        "JournalUnsupportedSchema",
        "JournalOfflineHistoryUnsupported",
        "JournalNamedRecipientHistoryUnsupported",
        "JournalConstructionHistoryUnsupported",
        "JournalInvalidBinding",
        "JournalConflict",
        "JournalNotFound",
        "JournalLiveAuthorization",
        "JournalInputReserved",
        "JournalBudgetExceeded",
        "JournalLimit",
    ];
    const FLOW_NESTED_STORE: &[&str] = &[
        "StoreStorageSecurity",
        "StoreDatabase",
        "StoreEncoding",
        "StorePoisoned",
        "StoreIdempotencyConflict",
        "StoreRevisionConflict",
        "StoreNotFound",
        "StoreAlreadyExists",
        "StoreInvalidInput",
        "StoreUnsupportedSchema",
        "StoreRecoveryRequired",
        "StoreWriterEpochMismatch",
        "StoreLiveAuthorizationExists",
        "StoreInputReserved",
        "StoreResourceExhausted",
        "StoreBudgetExceeded",
        "StoreInvalidTransition",
        "StoreFile",
    ];
    const FLOW_NESTED_AUTHORITY: &[&str] = &[
        "AuthorityInvalidBinding",
        "AuthorityPermission",
        "AuthorityStaleHead",
        "AuthorityConflict",
        "AuthorityInactive",
        "AuthorityRecoveryRequired",
        "AuthorityExpired",
        "AuthorityPolicyDenied",
        "AuthorityBudgetExceeded",
        "AuthorityInputReserved",
        "AuthorityObligationReserved",
        "AuthorityLimit",
        "AuthorityStorage",
        "AuthorityCorruptHistory",
        "AuthorityPermanentStopUnavailable",
        "AuthorityOfflineHistoryUnsupported",
        "AuthorityConstructionHistoryUnsupported",
        "AuthorityUnsupportedVersion",
        "AuthorityAuthentication",
        "AuthorityUncertain",
        "AuthorityResolutionUnavailable",
        "AuthoritySessionRequired",
        "AuthoritySessionPending",
    ];
    const FLOW_NESTED_WALLET_KEY_USE: &[&str] = &[
        "WalletKeyUsePermission",
        "WalletKeyUsePolicy",
        "WalletKeyUseSelectionExpired",
        "WalletKeyUseStorage",
        "WalletKeyUseRecoveryRequired",
        "WalletKeyUseStateChanged",
        "WalletKeyUseExpiry",
        "WalletKeyUseSync",
    ];
    const FLOW_NESTED_STORAGE_SECURITY: &[&str] = &[
        "StorageSecurityUnsupportedPlatform",
        "StorageSecurityQuarantinedDatabase",
        "StorageSecurityRecoveredGeneration",
        "StorageSecurityGenerationArchive",
        "StorageSecurityUninitializedDatabase",
        "StorageSecurityUnsafePath",
        "StorageSecurityAlreadyExists",
        "StorageSecurityMissingDatabase",
        "StorageSecurityPlaintextRefused",
        "StorageSecurityUnqualifiedRuntime",
        "StorageSecurityAuthenticationFailed",
        "StorageSecurityDatabase",
        "StorageSecurityIo",
        "StorageSecuritySnapshotLimit",
        "StorageSecuritySourceChanged",
    ];
    const FLOW_NESTED_SYNC: &[&str] = &[
        "SyncAccessDenied",
        "SyncInvalidRequest",
        "SyncInterrupted",
        "SyncReconciliationRequired",
        "SyncInvalidResponse",
        "SyncResourceLimit",
        "SyncNoCurrentObservation",
        "SyncWallet",
        "SyncChain",
    ];
    const FLOW_CHECK_SITES: &[&str] = &[
        "ExchangeInitial",
        "BeforeConnect",
        "AfterConnect",
        "BeforeHandshakeIo",
        "AfterHandshake",
        "AfterPeerBinding",
        "AfterRequestBuild",
        "BeforeRequestWrite",
        "AfterRequestWrite",
        "AfterResponseRead",
    ];
    const FLOW_CHECKPOINTS: &[&str] = &[
        "EntryDeadline",
        "DeadlineSelection",
        "ConnectRemaining",
        "BeforeCallback",
        "Callback",
        "AfterCallback",
        "Operation",
        "Validation",
    ];
    fn flow_codes(domain: &str) -> Option<&'static [&'static str]> {
        match domain {
            "Signer" => Some(FLOW_SIGNER_CODES),
            "Bridge" => Some(FLOW_BRIDGE_CODES),
            "Authority" => Some(FLOW_AUTHORITY_CODES),
            "Journal" => Some(FLOW_JOURNAL_CODES),
            "WalletKeyUse" => Some(FLOW_WALLET_KEY_USE_CODES),
            "Store" => Some(FLOW_STORE_CODES),
            _ => None,
        }
    }
    fn flow_nested(domain: &str, code: &str) -> &'static [&'static str] {
        match (domain, code) {
            ("Signer", "ConsentJournal") => FLOW_NESTED_JOURNAL,
            ("Bridge", "Journal") => FLOW_NESTED_JOURNAL,
            ("Signer", "Store") => FLOW_NESTED_STORE,
            ("Bridge", "Authority") => FLOW_NESTED_AUTHORITY,
            ("Bridge", "Wallet") => FLOW_NESTED_WALLET_KEY_USE,
            ("Journal", "Storage") => FLOW_NESTED_STORAGE_SECURITY,
            ("Store", "StorageSecurity") => FLOW_NESTED_STORAGE_SECURITY,
            ("WalletKeyUse", "Sync") => FLOW_NESTED_SYNC,
            _ => &[],
        }
    }
    fn optional_enum(value: Option<&str>, members: &[&str]) -> bool {
        value.is_none_or(|value| members.contains(&value))
    }
    fn duration(value: Option<u32>) -> bool {
        value.is_none_or(|value| value <= 600_000_000)
    }
    #[derive(serde::Deserialize, serde::Serialize)]
    #[serde(deny_unknown_fields)]
    struct PublicFlowError {
        stage: String,
        domain: String,
        code: String,
        #[serde(deserialize_with = "required_history_nullable")]
        nested_code: Option<String>,
    }
    impl PublicFlowError {
        fn valid(&self) -> bool {
            FLOW_STAGE.contains(&self.stage.as_str())
                && flow_codes(&self.domain).is_some_and(|codes| codes.contains(&self.code.as_str()))
                && self
                    .nested_code
                    .as_deref()
                    .is_none_or(|code| flow_nested(&self.domain, &self.code).contains(&code))
        }
    }
    #[derive(serde::Deserialize, serde::Serialize)]
    #[serde(deny_unknown_fields)]
    struct PublicFlowCompletion {
        #[serde(deserialize_with = "required_history_nullable")]
        purpose: Option<String>,
        result: String,
        receive: String,
        presentation: String,
    }
    impl PublicFlowCompletion {
        fn valid(&self) -> bool {
            optional_enum(self.purpose.as_deref(), FLOW_JOB_PURPOSE)
                && FLOW_RESULT.contains(&self.result.as_str())
                && FLOW_RECEIVE.contains(&self.receive.as_str())
                && FLOW_PRESENTATION.contains(&self.presentation.as_str())
                && (self.purpose.is_some()
                    || (self.result == "NotObserved"
                        && self.presentation == "NotObserved"
                        && matches!(self.receive.as_str(), "NotObserved" | "Missing")))
                && (self.receive != "Received"
                    || (self.purpose.is_some()
                        && matches!(self.result.as_str(), "ReturnedOk" | "ReturnedErr")))
                && (!matches!(self.receive.as_str(), "Pending" | "Disconnected")
                    || (self.result == "NotObserved" && self.presentation == "NotObserved"))
                && (self.presentation != "Accepted"
                    || (self.receive == "Received" && self.result == "ReturnedOk"))
                && (self.presentation != "Suppressed"
                    || matches!(self.receive.as_str(), "Received" | "Invalidated"))
        }
    }
    #[derive(serde::Deserialize, serde::Serialize)]
    #[serde(deny_unknown_fields)]
    struct PublicFlowCallOutcomes {
        writer_acquire: String,
        writer_activate: String,
        active_verify: String,
        reconciliation: String,
        session_invalidation: String,
        release: String,
        request_retention: String,
        reservation: String,
        permit_retention: String,
        key_use: String,
        result_retention: String,
    }
    impl PublicFlowCallOutcomes {
        fn valid(&self) -> bool {
            [
                self.writer_acquire.as_str(),
                self.writer_activate.as_str(),
                self.active_verify.as_str(),
                self.reconciliation.as_str(),
                self.session_invalidation.as_str(),
                self.release.as_str(),
                self.request_retention.as_str(),
                self.reservation.as_str(),
                self.permit_retention.as_str(),
                self.key_use.as_str(),
                self.result_retention.as_str(),
            ]
            .into_iter()
            .all(|value| FLOW_CALL_OUTCOME.contains(&value))
        }
    }
    #[derive(serde::Deserialize, serde::Serialize)]
    #[serde(deny_unknown_fields)]
    struct PublicFlowMeasurement {
        #[serde(deserialize_with = "required_history_nullable")]
        phase: Option<String>,
        #[serde(deserialize_with = "required_history_nullable")]
        check_site: Option<String>,
        checkpoint: String,
        #[serde(deserialize_with = "required_history_nullable")]
        selected_limit: Option<String>,
        #[serde(deserialize_with = "required_history_nullable")]
        selected_budget_us: Option<u32>,
        #[serde(deserialize_with = "required_history_nullable")]
        caller_remaining_at_budget_start_us: Option<u32>,
        #[serde(deserialize_with = "required_history_nullable")]
        caller_remaining_at_failure_us: Option<u32>,
        #[serde(deserialize_with = "required_history_nullable")]
        selected_remaining_at_failure_us: Option<u32>,
        operation_elapsed_us: u32,
        #[serde(deserialize_with = "required_history_nullable")]
        exchange_elapsed_us: Option<u32>,
        pre_budget_callback_calls: u32,
        pre_budget_callback_us: u32,
        operation_cost: PublicHistoryCost,
        #[serde(deserialize_with = "required_history_nullable")]
        exchange_cost: Option<PublicHistoryCost>,
        clamped: bool,
        incomplete: bool,
    }
    impl PublicFlowMeasurement {
        fn valid(&self, purpose: &str) -> bool {
            self.phase.as_deref().is_none_or(|phase| phase == purpose)
                && optional_enum(self.check_site.as_deref(), FLOW_CHECK_SITES)
                && FLOW_CHECKPOINTS.contains(&self.checkpoint.as_str())
                && optional_enum(self.selected_limit.as_deref(), &["Caller", "Exchange"])
                && [
                    self.selected_budget_us,
                    self.caller_remaining_at_budget_start_us,
                    self.caller_remaining_at_failure_us,
                    self.selected_remaining_at_failure_us,
                    self.exchange_elapsed_us,
                ]
                .into_iter()
                .all(duration)
                && self.operation_elapsed_us <= 600_000_000
                && self.pre_budget_callback_us <= 600_000_000
                && self.pre_budget_callback_calls <= 1
                && self.operation_cost.valid()
                && self
                    .exchange_cost
                    .as_ref()
                    .is_none_or(PublicHistoryCost::valid)
                && (purpose != "Reserve"
                    || (self.caller_remaining_at_budget_start_us.is_none()
                        && self.caller_remaining_at_failure_us.is_none()
                        && optional_enum(self.selected_limit.as_deref(), &["Exchange"])))
        }
    }
    #[derive(serde::Deserialize, serde::Serialize)]
    #[serde(deny_unknown_fields)]
    struct PublicFlowLowerCall {
        purpose: String,
        stage: String,
        authority_code: String,
        #[serde(deserialize_with = "required_history_nullable")]
        io_kind: Option<String>,
        #[serde(deserialize_with = "required_history_nullable")]
        callback_stage: Option<String>,
        measurement: PublicFlowMeasurement,
    }
    impl PublicFlowLowerCall {
        fn valid(&self) -> bool {
            FLOW_TRANSPORT_PURPOSE.contains(&self.purpose.as_str())
                && FLOW_TRANSPORT_STAGE.contains(&self.stage.as_str())
                && FLOW_AUTHORITY_CODE.contains(&self.authority_code.as_str())
                && optional_enum(
                    self.io_kind.as_deref(),
                    &["Timeout", "Closed", "Refused", "Other"],
                )
                && optional_enum(self.callback_stage.as_deref(), FLOW_CALLBACK_STAGE)
                && self.measurement.valid(&self.purpose)
        }
    }
    #[derive(serde::Deserialize, serde::Serialize)]
    #[serde(deny_unknown_fields)]
    struct PublicDurableFlow {
        version: u8,
        operation: String,
        #[serde(deserialize_with = "required_history_nullable")]
        first_error: Option<PublicFlowError>,
        #[serde(deserialize_with = "required_history_nullable")]
        terminal_error: Option<PublicFlowError>,
        fixture_result: String,
        completion: PublicFlowCompletion,
        call_outcomes: PublicFlowCallOutcomes,
        #[serde(deserialize_with = "required_history_nullable")]
        lower_call_measurement: Option<PublicFlowLowerCall>,
        clamped: bool,
        incomplete: bool,
    }
    impl PublicDurableFlow {
        fn valid(&self) -> bool {
            self.version == 1
                && FLOW_OPERATION.contains(&self.operation.as_str())
                && self.fixture_result == "ReturnedErr"
                && self.first_error.as_ref().is_none_or(PublicFlowError::valid)
                && self
                    .terminal_error
                    .as_ref()
                    .is_none_or(PublicFlowError::valid)
                && self.completion.valid()
                && self.call_outcomes.valid()
                && self.lower_call_measurement.as_ref().is_none_or(|lower| {
                    lower.valid()
                        && (!lower.measurement.clamped || self.clamped)
                        && (!lower.measurement.incomplete || self.incomplete)
                })
        }
    }
    fn flow_error(value: &DurableFlowErrorV1) -> PublicFlowError {
        PublicFlowError {
            stage: flow_stage_label(value.stage()).into(),
            domain: flow_error_domain_label(value.domain()).into(),
            code: flow_error_code_label(value.code()).into(),
            nested_code: value
                .nested_code()
                .map(|code| flow_nested_code_label(code).into()),
        }
    }
    fn flow_cost(value: &CheckedHistoryCostV1) -> PublicHistoryCost {
        PublicHistoryCost {
            callback_calls: value.callback_calls(),
            callback_us: value.callback_us(),
            callback_max_us: value.callback_max_us(),
            connect_calls: value.connect_calls(),
            connect_us: value.connect_us(),
            handshake_calls: value.handshake_calls(),
            handshake_us: value.handshake_us(),
            frame_write_calls: value.frame_write_calls(),
            frame_write_us: value.frame_write_us(),
            frame_read_calls: value.frame_read_calls(),
            frame_read_us: value.frame_read_us(),
        }
    }
    fn flow_phase(value: CheckedHistoryPhaseV1) -> Option<&'static str> {
        match value {
            CheckedHistoryPhaseV1::Acquire => Some("Acquire"),
            CheckedHistoryPhaseV1::Activate => Some("Activate"),
            CheckedHistoryPhaseV1::Verify => Some("Verify"),
            CheckedHistoryPhaseV1::Reserve => Some("Reserve"),
            CheckedHistoryPhaseV1::Snapshot
            | CheckedHistoryPhaseV1::Page
            | CheckedHistoryPhaseV1::Admission => None,
        }
    }
    fn flow_measurement(value: &CheckedHistoryMeasurementV1) -> Option<PublicFlowMeasurement> {
        // Reject an old purpose rather than reinterpret it as unavailable Flow.
        let phase = match value.phase() {
            Some(phase) => Some(flow_phase(phase)?.into()),
            None => None,
        };
        Some(PublicFlowMeasurement {
            phase,
            check_site: value
                .check_site()
                .map(|site| history_check_site_label(site).into()),
            checkpoint: history_checkpoint_label(value.checkpoint()).into(),
            selected_limit: value
                .selected_limit()
                .map(|limit| history_selected_limit_label(limit).into()),
            selected_budget_us: value.selected_budget_us(),
            caller_remaining_at_budget_start_us: value.caller_remaining_at_budget_start_us(),
            caller_remaining_at_failure_us: value.caller_remaining_at_failure_us(),
            selected_remaining_at_failure_us: value.selected_remaining_at_failure_us(),
            operation_elapsed_us: value.history_elapsed_us(),
            exchange_elapsed_us: value.exchange_elapsed_us(),
            pre_budget_callback_calls: value.pre_budget_callback_calls().into(),
            pre_budget_callback_us: value.pre_budget_callback_us(),
            operation_cost: flow_cost(value.history_cost()),
            exchange_cost: value.exchange_cost().map(flow_cost),
            clamped: value.clamped(),
            incomplete: value.incomplete(),
        })
    }
    fn flow_lower(value: &DurableFlowTransportFailureV1) -> Option<PublicFlowLowerCall> {
        Some(PublicFlowLowerCall {
            purpose: flow_transport_purpose_label(value.purpose()).into(),
            stage: flow_transport_stage_label(value.stage()).into(),
            authority_code: flow_authority_code_label(value.authority_code()).into(),
            io_kind: value
                .io_kind()
                .map(|kind| admission_io_kind_label(kind).into()),
            callback_stage: value
                .callback_stage()
                .map(|stage| flow_callback_stage_label(stage).into()),
            measurement: flow_measurement(value.measurement())?,
        })
    }
    fn flow_public(value: &DurableFlowDiagnosticV1) -> Option<PublicDurableFlow> {
        // Never manufacture a record for a successful fixture.
        if !matches!(value.fixture_result(), DurableFlowResultV1::ReturnedErr) {
            return None;
        }
        let lower_call_measurement = match value.lower_call_measurement() {
            Some(lower) => Some(flow_lower(lower)?),
            None => None,
        };
        let completion = value.completion();
        let calls = value.call_outcomes();
        Some(PublicDurableFlow {
            version: 1,
            operation: flow_operation_label(value.operation()).into(),
            first_error: value.first_error().map(flow_error),
            terminal_error: value.terminal_error().map(flow_error),
            fixture_result: flow_result_label(value.fixture_result()).into(),
            completion: PublicFlowCompletion {
                purpose: completion
                    .purpose()
                    .map(|purpose| flow_job_purpose_label(purpose).into()),
                result: flow_result_label(completion.result()).into(),
                receive: flow_receive_label(completion.receive()).into(),
                presentation: flow_presentation_label(completion.presentation()).into(),
            },
            call_outcomes: PublicFlowCallOutcomes {
                writer_acquire: flow_call_outcome_label(calls.writer_acquire()).into(),
                writer_activate: flow_call_outcome_label(calls.writer_activate()).into(),
                active_verify: flow_call_outcome_label(calls.active_verify()).into(),
                reconciliation: flow_call_outcome_label(calls.reconciliation()).into(),
                session_invalidation: flow_call_outcome_label(calls.session_invalidation()).into(),
                release: flow_call_outcome_label(calls.release()).into(),
                request_retention: flow_call_outcome_label(calls.request_retention()).into(),
                reservation: flow_call_outcome_label(calls.reservation()).into(),
                permit_retention: flow_call_outcome_label(calls.permit_retention()).into(),
                key_use: flow_call_outcome_label(calls.key_use()).into(),
                result_retention: flow_call_outcome_label(calls.result_retention()).into(),
            },
            lower_call_measurement,
            clamped: value.clamped(),
            incomplete: value.incomplete(),
        })
    }
    // Both producer and consumers use this exact bounded, ordered serializer.
    fn canonical_payload(value: &PublicDurableFlow) -> Option<String> {
        if !value.valid() {
            return None;
        }
        let text = serde_json::to_string(value).ok()?;
        (text.len() <= MAX_PAYLOAD).then_some(text)
    }
    fn parse_payload(text: &str) -> Option<PublicDurableFlow> {
        if text.len() > MAX_PAYLOAD {
            return None;
        }
        let value: PublicDurableFlow = serde_json::from_str(text).ok()?;
        value.valid().then_some(value)
    }
    fn write_private_record(mut output: impl std::io::Write, value: &PublicDurableFlow) {
        let Some(text) = canonical_payload(value) else {
            return;
        };
        let _ = writeln!(output, "\n{PRIVATE_PREFIX}{text}]");
    }
    pub(crate) fn emit_durable_flow(value: &DurableFlowDiagnosticV1) {
        let Some(value) = flow_public(value) else {
            return;
        };
        write_private_record(std::io::stderr().lock(), &value);
    }
    #[derive(Default)]
    pub(crate) struct DurableFlowCapture {
        record: Option<String>,
        invalid: bool,
    }
    impl DurableFlowCapture {
        pub(crate) fn retained_bytes(&self) -> usize {
            self.record.as_ref().map_or(0, String::len)
        }
        pub(crate) fn discard_for_budget(&mut self) {
            if self.record.take().is_some() {
                self.invalid = true;
            }
        }
        pub(crate) fn capture_line(&mut self, line: &str, available: usize) {
            if !line.starts_with("[DURABLE_FLOW_V1") && line != INVALID {
                return;
            }
            if self.invalid {
                return;
            }
            let canonical = line
                .strip_prefix(PRIVATE_PREFIX)
                .and_then(|line| line.strip_suffix(']'))
                .and_then(parse_payload)
                .as_ref()
                .and_then(canonical_payload)
                .map(|text| format!("{PUBLIC_PREFIX}{text}"));
            if self.record.is_none() {
                if let Some(record) = canonical {
                    if record.len() <= available {
                        self.record = Some(record);
                        return;
                    }
                }
            }
            self.record = None;
            self.invalid = true;
        }
        pub(crate) fn public_lines(&self) -> Vec<&str> {
            if self.invalid {
                vec![INVALID]
            } else {
                self.record.as_deref().into_iter().collect()
            }
        }
    }
    #[cfg(test)]
    pub(crate) const DURABLE_FLOW_MAXIMAL_TEST_JSON: &str = r#"{"version":1,"operation":"WriterReconcile","first_error":{"stage":"AuthorizationSource","domain":"Signer","code":"ConsentJournal","nested_code":"JournalNamedRecipientHistoryUnsupported"},"terminal_error":{"stage":"AuthorizationSource","domain":"Signer","code":"ConsentJournal","nested_code":"JournalNamedRecipientHistoryUnsupported"},"fixture_result":"ReturnedErr","completion":{"purpose":"ActivationPrepare","result":"NotObserved","receive":"Disconnected","presentation":"NotObserved"},"call_outcomes":{"writer_acquire":"ReturnedErr","writer_activate":"ReturnedErr","active_verify":"ReturnedErr","reconciliation":"ReturnedErr","session_invalidation":"ReturnedErr","release":"ReturnedErr","request_retention":"ReturnedErr","reservation":"ReturnedErr","permit_retention":"ReturnedErr","key_use":"ReturnedErr","result_retention":"ReturnedErr"},"lower_call_measurement":{"purpose":"Activate","stage":"CommittedHeadValidation","authority_code":"ConstructionHistoryUnsupported","io_kind":"Timeout","callback_stage":"WorkspaceCurrent","measurement":{"phase":"Activate","check_site":"BeforeRequestWrite","checkpoint":"DeadlineSelection","selected_limit":"Exchange","selected_budget_us":600000000,"caller_remaining_at_budget_start_us":600000000,"caller_remaining_at_failure_us":600000000,"selected_remaining_at_failure_us":600000000,"operation_elapsed_us":600000000,"exchange_elapsed_us":600000000,"pre_budget_callback_calls":1,"pre_budget_callback_us":600000000,"operation_cost":{"callback_calls":1000000,"callback_us":600000000,"callback_max_us":600000000,"connect_calls":1000000,"connect_us":600000000,"handshake_calls":1000000,"handshake_us":600000000,"frame_write_calls":1000000,"frame_write_us":600000000,"frame_read_calls":1000000,"frame_read_us":600000000},"exchange_cost":{"callback_calls":1000000,"callback_us":600000000,"callback_max_us":600000000,"connect_calls":1000000,"connect_us":600000000,"handshake_calls":1000000,"handshake_us":600000000,"frame_write_calls":1000000,"frame_write_us":600000000,"frame_read_calls":1000000,"frame_read_us":600000000},"clamped":false,"incomplete":false}},"clamped":false,"incomplete":false}"#;

    #[cfg(test)]
    mod tests {
        use super::*;
        fn fixture() -> serde_json::Value {
            serde_json::from_str(DURABLE_FLOW_MAXIMAL_TEST_JSON).unwrap()
        }
        fn accepted(value: &serde_json::Value) -> bool {
            parse_payload(&value.to_string()).is_some()
        }
        fn object_paths(value: &serde_json::Value, path: String, out: &mut Vec<String>) {
            if let Some(object) = value.as_object() {
                out.push(path.clone());
                for (key, child) in object {
                    object_paths(child, format!("{path}/{key}"), out);
                }
            }
        }
        #[test]
        fn durable_flow_maximal_canonical_record_fits_fixed_slot() {
            // This proves production DTO serializer/parser parity, not a runtime history.
            let value = parse_payload(DURABLE_FLOW_MAXIMAL_TEST_JSON).unwrap();
            let text = canonical_payload(&value).unwrap();
            assert_eq!(text.len(), 2130);
            assert!(text.len() <= MAX_PAYLOAD);
            assert_eq!(text, DURABLE_FLOW_MAXIMAL_TEST_JSON);
            let escaped = text.replacen("WriterReconcile", "\\u0057riterReconcile", 1);
            assert_eq!(canonical_payload(&parse_payload(&escaped).unwrap()).unwrap(), text);
            let mut slot = DurableFlowCapture::default();
            slot.capture_line(&format!("{PRIVATE_PREFIX}{text}]"), 8192);
            assert_eq!(
                slot.public_lines(),
                vec![format!("{PUBLIC_PREFIX}{text}").as_str()]
            );
            assert_eq!(
                canonical_payload(&parse_payload(&text).unwrap()).unwrap(),
                text
            );
        }
        #[test]
        fn durable_flow_maximal_error_pair_is_closed() {
            let mut maximum = 0;
            let all_nested: Vec<_> = FLOW_ERROR_DOMAIN
                .iter()
                .flat_map(|domain| {
                    flow_codes(domain)
                        .unwrap()
                        .iter()
                        .flat_map(move |code| flow_nested(domain, code).iter().copied())
                })
                .collect();
            for domain in FLOW_ERROR_DOMAIN {
                for code in flow_codes(domain).unwrap() {
                    for nested in std::iter::once(None)
                        .chain(flow_nested(domain, code).iter().copied().map(Some))
                    {
                        let error = PublicFlowError {
                            stage: "AuthorizationSource".into(),
                            domain: (*domain).into(),
                            code: (*code).into(),
                            nested_code: nested.map(str::to_owned),
                        };
                        assert!(error.valid());
                        maximum = maximum.max(serde_json::to_string(&error).unwrap().len());
                    }
                    for nested in &all_nested {
                        let error = PublicFlowError {
                            stage: "AuthorizationSource".into(),
                            domain: (*domain).into(),
                            code: (*code).into(),
                            nested_code: Some((*nested).into()),
                        };
                        assert_eq!(error.valid(), flow_nested(domain, code).contains(nested));
                    }
                }
            }
            assert_eq!(maximum, 129);
            for (domain, code) in [
                ("Wallet", "Storage"),
                ("Signer", "SessionRequired"),
                ("Bridge", "Database"),
            ] {
                let error = PublicFlowError {
                    stage: "FixtureState".into(),
                    domain: domain.into(),
                    code: code.into(),
                    nested_code: None,
                };
                assert!(!error.valid());
            }
        }
        #[test]
        fn durable_flow_maximal_component_lengths() {
            let value = fixture();
            for (values, selected) in [
                (FLOW_OPERATION, "WriterReconcile"),
                (FLOW_STAGE, "AuthorizationSource"),
                (FLOW_JOB_PURPOSE, "ActivationPrepare"),
                (FLOW_TRANSPORT_PURPOSE, "Activate"),
                (FLOW_TRANSPORT_STAGE, "CommittedHeadValidation"),
                (FLOW_AUTHORITY_CODE, "ConstructionHistoryUnsupported"),
                (FLOW_CALLBACK_STAGE, "WorkspaceCurrent"),
                (FLOW_CALL_OUTCOME, "ReturnedErr"),
                (FLOW_CHECK_SITES, "BeforeRequestWrite"),
                (FLOW_CHECKPOINTS, "DeadlineSelection"),
                (&["Caller", "Exchange"][..], "Exchange"),
                (&["Timeout", "Closed", "Refused", "Other"][..], "Timeout"),
            ] {
                assert_eq!(values.iter().map(|v| v.len()).max(), Some(selected.len()));
                assert!(serde_json::to_string(selected).unwrap().len() >= 4); // null
            }
            let mut max_completion = 0;
            for purpose in std::iter::once(None).chain(FLOW_JOB_PURPOSE.iter().copied().map(Some)) {
                for result in FLOW_RESULT {
                    for receive in FLOW_RECEIVE {
                        for presentation in FLOW_PRESENTATION {
                            let c = PublicFlowCompletion {
                                purpose: purpose.map(str::to_owned),
                                result: (*result).into(),
                                receive: (*receive).into(),
                                presentation: (*presentation).into(),
                            };
                            if c.valid() {
                                max_completion =
                                    max_completion.max(serde_json::to_string(&c).unwrap().len());
                            }
                        }
                    }
                }
            }
            assert_eq!(
                max_completion,
                serde_json::to_string(
                    &parse_payload(DURABLE_FLOW_MAXIMAL_TEST_JSON)
                        .unwrap()
                        .completion
                )
                .unwrap()
                .len()
            );
            assert_eq!(serde_json::to_string(&false).unwrap().len(), 5);
            assert_eq!(600_000_000u32.to_string().len(), 9);
            assert_eq!(1_000_000u32.to_string().len(), 7);
            assert_eq!(value["call_outcomes"].as_object().unwrap().len(), 11);
        }
        #[test]
        fn durable_flow_payload_cap_exact_boundary() {
            let exact = format!(
                "{}{}",
                DURABLE_FLOW_MAXIMAL_TEST_JSON,
                " ".repeat(MAX_PAYLOAD - DURABLE_FLOW_MAXIMAL_TEST_JSON.len())
            );
            assert_eq!(exact.len(), 4096);
            assert_eq!(
                canonical_payload(&parse_payload(&exact).unwrap()).unwrap(),
                DURABLE_FLOW_MAXIMAL_TEST_JSON
            );
            assert!(parse_payload(&(exact + " ")).is_none());
            assert!(parse_payload(&" ".repeat(4097)).is_none());
        }
        #[test]
        fn durable_flow_getter_labels_are_closed() {
            for (value, label) in FLOW_OPERATION_LABELS {
                assert_eq!(flow_operation_label(*value), *label);
                assert!(FLOW_OPERATION.contains(label));
            }
            for (value, label) in FLOW_STAGE_LABELS {
                assert_eq!(flow_stage_label(*value), *label);
                assert!(FLOW_STAGE.contains(label));
            }
            for (value, label) in FLOW_ERROR_DOMAIN_LABELS {
                assert_eq!(flow_error_domain_label(*value), *label);
                assert!(FLOW_ERROR_DOMAIN.contains(label));
            }
            for (value, label) in FLOW_JOB_PURPOSE_LABELS {
                assert_eq!(flow_job_purpose_label(*value), *label);
                assert!(FLOW_JOB_PURPOSE.contains(label));
            }
            for (value, label) in FLOW_RESULT_LABELS {
                assert_eq!(flow_result_label(*value), *label);
                assert!(FLOW_RESULT.contains(label));
            }
            for (value, label) in FLOW_RECEIVE_LABELS {
                assert_eq!(flow_receive_label(*value), *label);
                assert!(FLOW_RECEIVE.contains(label));
            }
            for (value, label) in FLOW_PRESENTATION_LABELS {
                assert_eq!(flow_presentation_label(*value), *label);
                assert!(FLOW_PRESENTATION.contains(label));
            }
            for (value, label) in FLOW_CALL_OUTCOME_LABELS {
                assert_eq!(flow_call_outcome_label(*value), *label);
                assert!(FLOW_CALL_OUTCOME.contains(label));
            }
            for (value, label) in FLOW_TRANSPORT_PURPOSE_LABELS {
                assert_eq!(flow_transport_purpose_label(*value), *label);
                assert!(FLOW_TRANSPORT_PURPOSE.contains(label));
            }
            for (value, label) in FLOW_TRANSPORT_STAGE_LABELS {
                assert_eq!(flow_transport_stage_label(*value), *label);
                assert!(FLOW_TRANSPORT_STAGE.contains(label));
            }
            for (value, label) in FLOW_AUTHORITY_CODE_LABELS {
                assert_eq!(flow_authority_code_label(*value), *label);
                assert!(FLOW_AUTHORITY_CODE.contains(label));
            }
            for (value, label) in FLOW_CALLBACK_STAGE_LABELS {
                assert_eq!(flow_callback_stage_label(*value), *label);
                assert!(FLOW_CALLBACK_STAGE.contains(label));
            }
            for (value, label) in FLOW_ERROR_CODE_LABELS {
                assert_eq!(flow_error_code_label(*value), *label);
            }
            for (value, label) in FLOW_NESTED_CODE_LABELS {
                assert_eq!(flow_nested_code_label(*value), *label);
            }
            for (value, expected) in [
                (CheckedHistoryPhaseV1::Acquire, "Acquire"),
                (CheckedHistoryPhaseV1::Activate, "Activate"),
                (CheckedHistoryPhaseV1::Verify, "Verify"),
                (CheckedHistoryPhaseV1::Reserve, "Reserve"),
            ] {
                assert_eq!(flow_phase(value), Some(expected));
            }
            for value in [
                CheckedHistoryPhaseV1::Snapshot,
                CheckedHistoryPhaseV1::Page,
                CheckedHistoryPhaseV1::Admission,
            ] {
                assert_eq!(flow_phase(value), None);
            }
        }
        #[test]
        fn durable_flow_parser_requires_exact_scopes() {
            let value = fixture();
            let text = value.to_string();
            let mut paths = Vec::new();
            object_paths(&value, String::new(), &mut paths);
            for path in paths {
                let object = value.pointer(&path).unwrap().as_object().unwrap();
                let fragment = value.pointer(&path).unwrap().to_string();
                let mut unknown = value.clone();
                unknown.pointer_mut(&path).unwrap()["private"] =
                    serde_json::json!("secret payload");
                assert!(!accepted(&unknown));
                for (key, entry) in object {
                    let mut missing = value.clone();
                    missing
                        .pointer_mut(&path)
                        .unwrap()
                        .as_object_mut()
                        .unwrap()
                        .remove(key);
                    assert!(!accepted(&missing));
                    let field = format!("{path}/{key}");
                    let nullable = matches!(
                        field.as_str(),
                        "/first_error"
                            | "/terminal_error"
                            | "/lower_call_measurement"
                            | "/first_error/nested_code"
                            | "/terminal_error/nested_code"
                            | "/completion/purpose"
                            | "/lower_call_measurement/io_kind"
                            | "/lower_call_measurement/callback_stage"
                            | "/lower_call_measurement/measurement/phase"
                            | "/lower_call_measurement/measurement/check_site"
                            | "/lower_call_measurement/measurement/selected_limit"
                            | "/lower_call_measurement/measurement/selected_budget_us"
                            | "/lower_call_measurement/measurement/caller_remaining_at_budget_start_us"
                            | "/lower_call_measurement/measurement/caller_remaining_at_failure_us"
                            | "/lower_call_measurement/measurement/selected_remaining_at_failure_us"
                            | "/lower_call_measurement/measurement/exchange_elapsed_us"
                            | "/lower_call_measurement/measurement/exchange_cost"
                    );
                    if !nullable {
                        let mut changed = value.clone();
                        *changed.pointer_mut(&field).unwrap() = serde_json::Value::Null;
                        assert!(!accepted(&changed));
                    }
                    if entry.is_object() {
                        for bad in [
                            serde_json::json!([]),
                            serde_json::json!(false),
                            serde_json::json!(1),
                            serde_json::json!("private"),
                        ] {
                            let mut changed = value.clone();
                            *changed.pointer_mut(&field).unwrap() = bad;
                            assert!(!accepted(&changed));
                        }
                    }
                    let duplicated = format!("{{\"{key}\":{entry},{}", &fragment[1..]);
                    assert!(parse_payload(&text.replacen(&fragment, &duplicated, 1)).is_none());
                    let escaped = format!("\\u{:04x}{}", key.as_bytes()[0], &key[1..]);
                    let duplicated = format!("{{\"{escaped}\":{entry},{}", &fragment[1..]);
                    assert!(parse_payload(&text.replacen(&fragment, &duplicated, 1)).is_none());
                }
            }
            for token in [
                "true",
                "false",
                "1.0",
                "1e0",
                "-1",
                "NaN",
                "Infinity",
                "-Infinity",
                "null",
                "[]",
                "{}",
                "\"1\"",
            ] {
                let text = DURABLE_FLOW_MAXIMAL_TEST_JSON.replacen(
                    "\"version\":1",
                    &format!("\"version\":{token}"),
                    1,
                );
                assert!(parse_payload(&text).is_none());
            }
        }
        #[test]
        fn durable_flow_parser_rejects_invalid_categories_and_bounds() {
            let original = fixture();
            let mut paths = Vec::new();
            object_paths(&original, String::new(), &mut paths);
            for path in paths {
                for (key, entry) in original.pointer(&path).unwrap().as_object().unwrap() {
                    if entry.is_number() {
                        let max = if key == "version" || key == "pre_budget_callback_calls" {
                            1
                        } else if key.ends_with("_calls") {
                            1_000_000
                        } else {
                            600_000_000
                        };
                        for bad in [
                            serde_json::json!(true),
                            serde_json::json!(false),
                            serde_json::json!(-1),
                            serde_json::json!(1.0),
                            serde_json::json!(max + 1),
                            serde_json::json!("0"),
                            serde_json::json!([]),
                            serde_json::json!({}),
                        ] {
                            let mut value = original.clone();
                            value.pointer_mut(&path).unwrap()[key] = bad;
                            assert!(!accepted(&value));
                        }
                    } else if entry.is_boolean() {
                        for bad in [
                            serde_json::json!(0),
                            serde_json::json!(null),
                            serde_json::json!("false"),
                        ] {
                            let mut value = original.clone();
                            value.pointer_mut(&path).unwrap()[key] = bad;
                            assert!(!accepted(&value));
                        }
                    } else if entry.is_string() {
                        for bad in [
                            serde_json::json!("private/path/token"),
                            serde_json::json!(false),
                            serde_json::json!([]),
                        ] {
                            let mut value = original.clone();
                            value.pointer_mut(&path).unwrap()[key] = bad;
                            assert!(!accepted(&value));
                        }
                    }
                }
            }
            for operation in FLOW_OPERATION {
                let mut value = original.clone();
                value["operation"] = serde_json::json!(operation);
                assert!(accepted(&value));
            }
            for stage in FLOW_STAGE {
                let mut value = original.clone();
                value["first_error"]["stage"] = serde_json::json!(stage);
                assert!(accepted(&value));
            }
            for state in FLOW_CALL_OUTCOME {
                for key in original["call_outcomes"].as_object().unwrap().keys() {
                    let mut value = original.clone();
                    value["call_outcomes"][key] = serde_json::json!(state);
                    assert!(accepted(&value));
                }
            }
            for (field, values) in [
                ("stage", FLOW_TRANSPORT_STAGE),
                ("authority_code", FLOW_AUTHORITY_CODE),
                ("callback_stage", FLOW_CALLBACK_STAGE),
            ] {
                for member in values {
                    let mut value = original.clone();
                    value["lower_call_measurement"][field] = serde_json::json!(member);
                    assert!(accepted(&value));
                }
            }
            for purpose in FLOW_TRANSPORT_PURPOSE {
                let mut value = original.clone();
                value["lower_call_measurement"]["purpose"] = serde_json::json!(purpose);
                value["lower_call_measurement"]["measurement"]["phase"] =
                    serde_json::json!(purpose);
                if *purpose == "Reserve" {
                    value["lower_call_measurement"]["measurement"]["caller_remaining_at_budget_start_us"] =
                        serde_json::Value::Null;
                    value["lower_call_measurement"]["measurement"]["caller_remaining_at_failure_us"] =
                        serde_json::Value::Null;
                }
                assert!(accepted(&value));
            }
        }
        #[test]
        fn durable_flow_null_completion_and_measurement_consistency() {
            let mut value = fixture();
            value["first_error"] = serde_json::Value::Null;
            value["terminal_error"] = serde_json::Value::Null;
            value["lower_call_measurement"] = serde_json::Value::Null;
            for receive in ["NotObserved", "Missing"] {
                value["completion"] = serde_json::json!({"purpose":null,"result":"NotObserved","receive":receive,"presentation":"NotObserved"});
                assert!(accepted(&value));
            }
            for receive in ["Pending", "Disconnected", "Received", "Invalidated"] {
                value["completion"]["receive"] = serde_json::json!(receive);
                assert!(!accepted(&value));
            }
            for (result, receive, presentation, valid) in [
                ("ReturnedOk", "Received", "Accepted", true),
                ("ReturnedErr", "Received", "Accepted", false),
                ("ReturnedErr", "Received", "Suppressed", true),
                ("ReturnedOk", "Invalidated", "Suppressed", true),
                ("NotObserved", "Invalidated", "Suppressed", true),
                ("ReturnedOk", "Disconnected", "NotObserved", false),
                ("ReturnedErr", "Missing", "NotObserved", true),
                ("NotObserved", "Pending", "NotObserved", true),
            ] {
                value["completion"] = serde_json::json!({"purpose":"Import","result":result,"receive":receive,"presentation":presentation});
                assert_eq!(accepted(&value), valid);
            }
            for flag in ["clamped", "incomplete"] {
                let mut value = fixture();
                value["lower_call_measurement"]["measurement"][flag] = serde_json::json!(true);
                assert!(!accepted(&value));
                value[flag] = serde_json::json!(true);
                assert!(accepted(&value));
            }
            let mut value = fixture();
            value["lower_call_measurement"]["measurement"]["phase"] = serde_json::json!("Verify");
            assert!(!accepted(&value));
            value["lower_call_measurement"]["measurement"]["phase"] = serde_json::Value::Null;
            assert!(accepted(&value));
            for field in [
                "phase",
                "check_site",
                "selected_limit",
                "selected_budget_us",
                "caller_remaining_at_budget_start_us",
                "caller_remaining_at_failure_us",
                "selected_remaining_at_failure_us",
                "exchange_elapsed_us",
                "exchange_cost",
            ] {
                value["lower_call_measurement"]["measurement"][field] = serde_json::Value::Null;
            }
            value["lower_call_measurement"]["measurement"]["operation_elapsed_us"] =
                serde_json::json!(0);
            assert!(accepted(&value));
            value["fixture_result"] = serde_json::json!("ReturnedOk");
            assert!(!accepted(&value));
        }
        #[test]
        fn durable_flow_capture_is_sticky_bounded_and_independent() {
            let valid = format!("{PRIVATE_PREFIX}{DURABLE_FLOW_MAXIMAL_TEST_JSON}]");
            for first in [
                &valid,
                "[DURABLE_FLOW_V1 {\"private\":\"secret\"}]",
                INVALID,
                "[DURABLE_FLOW_V1]",
            ] {
                let mut slot = DurableFlowCapture::default();
                slot.capture_line(first, 8192);
                slot.capture_line(&valid, 8192);
                assert_eq!(slot.public_lines(), vec![INVALID]);
                assert_eq!(slot.retained_bytes(), 0);
            }
            let mut slot = DurableFlowCapture::default();
            slot.capture_line(&valid, 1);
            slot.capture_line(&valid, 8192);
            assert_eq!(slot.public_lines(), vec![INVALID]);
            let mut slot = DurableFlowCapture::default();
            slot.capture_line(&format!("private {valid}"), 8192);
            assert!(slot.public_lines().is_empty());
            slot.capture_line(&valid, 8192);
            slot.discard_for_budget();
            assert_eq!(slot.public_lines(), vec![INVALID]);
            slot.capture_line(&valid, 8192);
            assert_eq!(slot.public_lines(), vec![INVALID]);
            let mut other = super::super::AdmissionDiagnosticCapture::default();
            other.capture_line(
                &format!(
                    "[SIGNER_ADMISSION_V1 {}]",
                    super::super::SIGNER_ADMISSION_TEST_JSON
                ),
                8192,
            );
            assert_eq!(other.public_lines().len(), 1);
            assert!(!other.public_lines()[0].contains("invalid=true"));
            struct FailedOutput;
            impl std::io::Write for FailedOutput {
                fn write(&mut self, _: &[u8]) -> std::io::Result<usize> {
                    Err(std::io::Error::other("private sentinel"))
                }
                fn flush(&mut self) -> std::io::Result<()> {
                    Err(std::io::Error::other("private sentinel"))
                }
            }
            let value = parse_payload(DURABLE_FLOW_MAXIMAL_TEST_JSON).unwrap();
            write_private_record(FailedOutput, &value); // Optional write error is ignored.
            let mut invalid = value;
            invalid.fixture_result = "ReturnedOk".into();
            let mut bytes = Vec::new();
            write_private_record(&mut bytes, &invalid);
            assert!(bytes.is_empty()); // Invalid serialization input is withheld.
        }
    }
}
#[cfg(all(test, feature = "synthetic-born-joined-qualification"))]
pub(super) use durable_flow_projection::DURABLE_FLOW_MAXIMAL_TEST_JSON;
#[cfg(feature = "synthetic-born-joined-qualification")]
pub(super) use durable_flow_projection::{DurableFlowCapture, emit_durable_flow};
