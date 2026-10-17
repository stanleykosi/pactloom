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
pub(super) fn host<T>(boundary: Boundary, operation: impl FnOnce() -> Result<T>) -> Result<T> {
    emit(boundary, Outcome::Begin);
    let result = operation();
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
        (E::PermanentStopUnavailable, "AuthorityPermanentStopUnavailable"),
        (E::OfflineHistoryUnsupported, "AuthorityOfflineHistoryUnsupported"),
        (E::ConstructionHistoryUnsupported, "AuthorityConstructionHistoryUnsupported"),
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
        assert_eq!(summary(valid.as_bytes()), format!("ObservedPlanWitnessOrigin:{expected}"));
        let invalid = format!("[JOINED_DIAGNOSTIC ObservedPlanWitnessOrigin {actual} private-data]");
        assert_eq!(summary(invalid.as_bytes()), "none");
    }
    assert_eq!(summary(b"[JOINED_DIAGNOSTIC WitnessPlanInput AuthorityInputOverBound]"), "WitnessPlanInput:AuthorityInputOverBound");
    assert_eq!(summary(b"[JOINED_DIAGNOSTIC WitnessPlanInput 262145]"), "none");
    assert_eq!(summary(b"[JOINED_DIAGNOSTIC WitnessPlanWorkerPrepare AuthorityUnsupportedVersion]"), "WitnessPlanWorkerPrepare:AuthorityUnsupportedVersion");
}
