#!/usr/bin/env python3
"""Closed disposable UI qualification projection. Import performs no I/O.

Recovery revision: public schema is new and no runtime gate is enabled by this
module. Passing these validators validates shape, not source evidence; only the
independent complete oracle may construct passed records, and the outer owner
must still verify whole-container removal before publishing a lifecycle pass.
"""
import json

SETUP_BOUNDARIES = frozenset("""
DeliveryAdmissionRetainedBinding
DeliveryAdmissionBeforeSendChannel
DeliveryAdmissionBeforeSendSource
DeliveryAdmissionBeforeWriteChannel
DeliveryAdmissionWriteFrame
DeliveryAdmissionWritePrecheck
DeliveryAdmissionWriteIo
DeliveryAdmissionWritePostcheck
DeliveryAdmissionFlushPrecheck
DeliveryAdmissionFlushIo
DeliveryAdmissionFlushPostcheck
DeliveryAdmissionAfterWriteSource
DeliveryAdmissionAfterWriteChannel
DeliveryAdmissionReadFrame
DeliveryAdmissionReadPrecheck
DeliveryAdmissionReadIo
DeliveryAdmissionReadPostcheck
DeliveryAdmissionAfterReadSource
DeliveryAdmissionAfterReadChannel
DeliveryAdmissionResponseRejected
DeliveryAdmissionResponseVariant
DeliveryAdmissionSnapshot
DeliveryAdmissionCommittedHead
DeliveryReceiveNativeDeadline
DeliveryReceiveRequest
DeliveryReceiveSource
DeliveryReceiveOriginalHistory
DeliveryReceiveOriginalBinding
DeliveryReceiveCurrentHistory
DeliveryReceiveRedisclosureBinding
DeliveryReceiveRecipientBinding
DeliveryReceiveViewingKey
DeliveryReceiveMaterialOwner
DeliveryReceiveLease
DeliveryReceiveNativeOrigin
DeliveryReceiveSourceUnderLease
DeliveryReceiveReceipts
DeliveryReceiveProposal
DeliveryReceiveAccount
DeliveryReceiveAccountBinding
DeliveryReceiveReviewerScope
DeliveryReceiveDeadline
DeliveryReceiveOriginalSource
DeliveryReceivePeer
DeliveryReceiveMaterialClock
DeliveryReceiveMaterialScope
DeliveryReceiveRequestDigest
DeliveryReceiveReadyWrite
DeliveryReceiveFrame
DeliveryReceiveCommandParse
DeliveryReceiveCommandBinding
DeliveryReceivePayloadLimit
DeliveryReceiveChunkDecode
DeliveryReceiveCurrentWrite
DeliveryReceiveReceivingWrite
DeliveryReceivePayloadBinding
DeliveryReceivePayloadParse
DeliveryReceivePayloadCanonical
DeliveryReceiveContributionBinding
DeliveryReceiveUnsignedDecode
DeliveryReceiveProvedDecode
DeliveryReceiveEconomics
DeliveryReceiveFinalBinding
DeliveryReceiveFinalSource
DeliveryReceiveFinalPeer
DeliveryReceiveFinalDeadline
DeliveryReceiveFinalMaterialClock
DeliveryReceiveFinalMaterialScope
DeliveryReceiveImportedWrite
DeliveryReceiveTerminal
DeliveryExportProofCurrent
DeliveryExportProofOrigin
DeliveryExportSourceBefore
DeliveryExportSourceAfter
DeliveryExportMetadataOrigin
DeliveryExportMarker
DeliveryExportHistory
DeliveryExportMaterialCeilings
DeliveryExportIntake
DeliveryExportVerifiedProof
DeliveryExportRoster
DeliveryExportPayload
DeliveryExportOutputActions
DeliveryExportRecipientBinding
DeliveryExportSources
DeliveryExportCheckpointScope
DeliveryExportProofPermission
DeliveryExportPermission
DeliveryExportReplayScope
DeliveryExportCommand
DeliveryExportReplayLookup
DeliveryExportDelta
DeliveryExportEntry
DeliveryRecipientMutex
DeliveryRecipientDeadline
DeliveryRecipientOrigin
DeliveryRecipientObserverClone
DeliveryRecipientWriteSerialize
DeliveryRecipientWriteLimit
DeliveryRecipientWriteDeadline
DeliveryRecipientWriteTimeout
DeliveryRecipientWriteIo
DeliveryRecipientWriteEmpty
DeliveryRecipientFrame
DeliveryRecipientResponseDecode
DeliveryRecipientResponseDigest
DeliveryRecipientResponse
DeliverySourceScopePredicate
DeliveryProofRolePredicate
DeliveryMaterialActionPredicate
DeliveryMaterialScopePredicate
DeliveryExportScopePredicate
DeliveryCredentialRegistration
DeliveryRedisclosure
DeliveryRedisclosurePrepare
DeliveryRedisclosureApprove
DeliveryRedisclosureServe
DeliveryArtifactImportStart
DeliveryArtifactImport
DeliverySourceOpen
DeliverySourceInspection
DeliverySourcePlan
DeliveryRecipientPrepare
DeliveryExportPreview
DeliveryExportApproval
DeliveryExportCommit
DeliveryExportPostcheck
DeliveryNativeCheck
DeliverySourceCheck
DeliverySourceExport
DeliveryOriginalReopen
DeliveryUnsupportedAudit
DeliveryNativeAdmission
DeliveryHistoricalRead
DeliveryIdentityCompare
DeliveryDurableMarker
DeliveryProducerKill
DeliveryProducerReap
DeliveryReaderReap
DeliveryRootCleanup
PrivateWorkspaceBootstrap
PrivateSourceSelect
PrivateWorkspaceReserve
PrivateWorkspaceAnchor
PrivateWorkspacePublish
PrivateWorkspaceInitialize
PrivateWorkspaceCandidate
PrivateWorkspaceCapture
PrivateWorkspaceIntake
PrivateWorkspaceObserve
PrivateWorkspaceCheckpoint
PrivateWorkspaceProof
PrivateWorkspaceFreeze
PrivateWorkspaceScanCleanup
PrivateWorkspaceDurableMarker
PrivateWorkspaceProducerKill
PrivateWorkspaceProducerReap
PrivateWorkspaceReaderOpen
PrivateWorkspaceReadFixed
PrivateWorkspaceIdentityCompare
PrivateWorkspaceReaderReap
PrivateWorkspaceRootCleanup
SignerAdmissionCallCallerDeadline
SignerAdmissionCallExchangeDeadline
SignerAdmissionCallSourceCallback
SignerAdmissionCallBounds
SignerAdmissionCallRequestValidation
SignerAdmissionCallBinding
SignerAdmissionCallConnect
SignerAdmissionCallHandshake
SignerAdmissionCallPeerBinding
SignerAdmissionCallRequestBuild
SignerAdmissionCallRequestWrite
SignerAdmissionCallResponseRead
SignerAdmissionCallResponse
SignerAdmissionCallSnapshotValidation
SignerAdmissionCallCommittedHeadValidation
SignerAdmissionCallFinalValidation
SignerAdmissionDispatchFixtureState
SignerAdmissionDispatchReviewCorrelation
SignerAdmissionDispatchNativeApproval
SignerAdmissionDispatchIntentRetention
SignerAdmissionDispatchSubmitCustody
SignerAdmissionDispatchSubmitIntent
SignerAdmissionDispatchSubmitInterval
SignerAdmissionDispatchSubmitWorkspace
SignerAdmissionDispatchAuthorityCall
SignerAdmissionDispatchWorkerCompletion
SignerAdmissionDispatchCommittedCorrelation
SignerAdmissionCallbackWorkspaceCurrent
SignerAdmissionCallbackCustody
SignerAdmissionCallbackRequestValidation
SignerAdmissionCallIoTimeout
SignerAdmissionCallIoClosed
SignerAdmissionCallIoRefused
SignerAdmissionCallIoOther
SignerAdmissionCallCallbackError
SignerAdmissionHistoryCallerDeadline
SignerAdmissionHistoryExchangeDeadline
SignerAdmissionHistorySourceCallback
SignerAdmissionHistorySnapshotConnect
SignerAdmissionHistorySnapshotHandshake
SignerAdmissionHistorySnapshotPeerBinding
SignerAdmissionHistorySnapshotRequestBuild
SignerAdmissionHistorySnapshotRequestWrite
SignerAdmissionHistorySnapshotResponseRead
SignerAdmissionHistorySnapshotResponse
SignerAdmissionHistorySnapshotValidation
SignerAdmissionHistoryPageConnect
SignerAdmissionHistoryPageHandshake
SignerAdmissionHistoryPagePeerBinding
SignerAdmissionHistoryPageRequestBuild
SignerAdmissionHistoryPageRequestWrite
SignerAdmissionHistoryPageResponseRead
SignerAdmissionHistoryPageResponse
SignerAdmissionHistoryPageValidation
SignerAdmissionHistoryEventReplay
SignerAdmissionHistoryFinalValidation
SignerAdmissionHistoryBounds
SignerAdmissionHistoryIoTimeout
SignerAdmissionHistoryIoClosed
SignerAdmissionHistoryIoRefused
SignerAdmissionHistoryIoOther
SignerAdmissionHistoryCallbackError
SignerAdmissionFixtureState
SignerAdmissionSource
SignerAdmissionHistory
SignerAdmissionRetainedIntent
SignerAdmissionTerms
SignerAdmissionRequestBuilder
SignerAdmissionExactRequest
SignerAdmissionLiveInterval
SignerAdmissionLocalIntent
SignerAdmissionIntentDisplay
SignerAdmissionReviewCustody
SignerAdmissionReviewDisplay
SignerAdmissionNativeStage
SignerAdmissionWorkerCompletion
DurableHostWitnessSetup
DurableHostWriterReconcile
DurableHostViewingSetup
DurableHostSign
DurableHostSignRetry
DurableHostResultHistory
DurableHostResultRetrieve
DurableHostResultRelay
DurableHostSignatureIntake
DurableHostSignatureStatus
DurableHostResultServiceStop
DurableHostSignatureUnion
DurableHostTransactionCheckpoint
DurableHostOpen
DurableHostPairStatus
DurableHostPairObserved
DurableHostAccept
DurableHostInitialDisclosure
DurableHostInitialObserved
DurableHostRecipient
DurableHostCaptureSetup
DurableHostCapture
DurableHostCaptureObserved
DurableHostCaptureCommitted
DurableHostIntake
DurableHostClose
DurableHostObserve
DurableHostCheckpoint
DurableHostProof
DurableHostFreeze
DurableHostReload
DurableHostRedisclosure
DurableHostReviewReady
DurableHostReviewExport
DurableHostReviewImported
DurableHostProviderStop
DurableEntryNativeOwnerCheck
DurableEntryVaultOpen
DurableEntryRetainedEnrollment
DurableEntryOriginalCommit
DurableEntryJournalOpen
DurableEntrySourceCheck
DurableEntryRuntimeActivation
DurableEntryWorkerResult
DurableEntryEndpointCreate
DurableEntryEndpointBind
DurableEntryEndpointPublish
DurableEntryPostEndpointSourceCheck
DurableEntryFixturePreflight
DurableEntryFixturePostActivation
ObservationClockRollback
ObservationClockWallExpired
ObservationClockMonotonicExpired
ObservationRetainedClockRead
ObservationRetainedClockDenied
ObservationAdmittedClockRead
ObservationAdmittedClockDenied
CompletionObservationDenied
CompletionPostReentryCurrent
CompletionReadBinding
CompletionConstructionTime
CompletionCallerBinding
CompletionConstructionRequest
EngineCheckpointClaim
EngineCheckpointPlan
EngineCheckpointRetained
EngineCheckpointParts
EngineCheckpointNative
EngineCheckpointHeld
EngineCheckpointRestriction
EngineCheckpointConstruct
EngineCheckpointInspect
EngineCheckpointActionLimit
EngineCheckpointConsent
EngineCheckpointReceipt
EngineCheckpointRecord
EngineCheckpointEnqueue
EngineCheckpointFinish
EngineCheckpointContext
CheckpointEngine
CheckpointWalletUnwind
CheckpointFinish
CheckpointObservations
CheckpointOutput
CheckpointBeforeClaim
CheckpointClaimMayExist
SignerPollCancelled
SignerPollDeadline
SignerPollTerminal
RosterConstructionIntoNamed
RosterConstructionNamedOwner
RosterConstructionFinalOwner
RosterConstructionCheck
RosterConstructionReserve
RosterConstructionReservedAppend
RosterConstructionConsume
RosterConstructionConsumedAppend
RosterConstructionSend
ConstructionClockTerminal
ConstructionClockLiveness
ConstructionClockWallRollback
ConstructionClockWallExpired
ConstructionClockMonotonicExpired
RosterCompletionClaimCheck
RosterCompletionClaimSign
RosterCompletionClaimGranted
RosterCompletionClaimClaim
RosterCompletionClaimClaimed
RosterCompletionClaimObserve
RosterCompletionClaimHistory
RosterCompletionClaimReentered
RosterCompletionClaimSend
NativeOwnerRevoked
NativeOwnerExpired
NativeOwnerParent
NativeOwnerRetirementParent
RosterOwnerEpoch
RosterWorkOpenCommonContext
RosterWorkPrepareCompletionWitness
RosterWorkPrepareReenteredConstruction
RosterWorkCommitCompletionPair
RosterWorkCommitCompletionWitness
RosterWorkCommitCompletionClaim
RosterWorkCommitReenteredConstruction
RosterCompletionWitnessCheck
RosterCompletionWitnessHistory
RosterCompletionWitnessHistoryBinding
RosterCompletionWitnessTransport
CompletionOriginal
CompletionPairApproval
CompletionPairBegin
CompletionPairFinish
CompletionReentryRequest
CompletionRequestApproval
CompletionReentryBegin
CompletionReentryFinish
CompletionConstructionBegin
CompletionConstructionFinish
RosterBirthHistoryGate
RosterBirthExtension
RosterBirthOriginal
RosterBirthLinkage
ContinuationRetainedSource
ContinuationAttemptedSource
ContinuationWriterSource
ContinuationHistoryReplay
ContinuationPairing
ContinuationPreparedReview
ContinuationSource
ContinuationBirthLink
ContinuationPreconstruction
ContinuationHistoryGate
ContinuationHistoryArchive
ContinuationRetainedReceipt
ContinuationPreviousLoad
ContinuationProposalCapacity
ContinuationProposalIndex
ContinuationAttemptSequence
ContinuationProposalValidation
ObservedPlanWitnessOrigin
WitnessPlanInput
WitnessPlanSelect
WitnessPlanInputUtf8
WitnessPlanPublicRefusal
WitnessPlanQualifiedEntry
WitnessPlanLaunch
WitnessPlanDrain
WitnessPlanPending
WitnessPlanApprove
WitnessPlanReceipt
WitnessPlanReceiptDigest
WitnessPlanExpectedParse
WitnessPlanDigestMatch
WitnessPlanWorkerPrepare
WitnessPlanWorkerApprove
CandidateRetainCurrent
CandidateRetainRequest
CandidateRetainBegin
CandidateRetainFinish
CandidateLeaseOrigin
CandidateRequestRemaining
InventoryLeaseOrigin
InventoryRequestSource
InventoryRequestProvenance
InventoryRequestBinding
InventoryRequestRemaining
InventorySourceOwner
InventorySourceNative
InventorySourceDeadline
InventorySourcePeer
InventorySourceOwnerBinding
InventorySourcePeerBinding
InventorySourceRetiredGrant
InventorySourceProcess
InventorySourceRetained
InventorySourceAdmission
InventorySourceHistory
InventorySourceWitness
InventoryWindowWallRollback
InventoryWindowWallExpired
InventoryWindowMonotonicExpired
InventoryNativeBinding
InventorySourceRequest
InventoryPeerConnection
InventoryObservedMissing
InventoryObservedLifetimeInvalid
InventoryObservedWallRollback
InventoryObservedSessionExpired
InventoryObservedAgeExpired
ScanAccessAccount
ScanAccessNativeBefore
ScanAccessRequest
ScanAccessTarget
ScanAccessHostAccess
ScanAccessPrincipal
ScanAccessEnrollmentPrincipal
ScanAccessRequestDigest
ScanAccessScopeDigest
ScanAccessImport
ScanAccessNativeAfter
ScanNativeAdmissionDeadline
ScanNativeLease
ScanNativeRemaining
ScanNativePurpose
ScanNativeAccount
ScanNativeProviderSource
ScanNativeProviderEndpoint
ScanNativeProviderTrust
RosterWorkOpen
RosterWorkPrepareIntent
RosterWorkPrepareReentry
RosterWorkPrepareSignature
RosterWorkPrepareExport
RosterWorkPrepareWitness
RosterWorkPrepareAcquire
RosterWorkPrepareActivate
RosterWorkPreparePublication
RosterWorkPrepareServe
RosterWorkPrepareContinuationProposal
RosterWorkPrepareContinuationSign
RosterWorkPrepareContinuationExport
RosterWorkPrepareContinuedReentry
RosterWorkPrepareContinuedServe
RosterWorkPreparePolicyExport
RosterWorkPrepareInventory
RosterWorkPrepareCandidateSelection
RosterWorkRetryAdmission
RosterWorkRetryContinuedAdmission
RosterWorkRetryAcquire
RosterWorkRetryActivate
RosterWorkCommitPair
RosterWorkCommitRetain
RosterWorkCommitReentry
RosterWorkCommitSign
RosterWorkCommitExport
RosterWorkCommitWitness
RosterWorkCommitAcquire
RosterWorkCommitActivate
RosterWorkCommitAdmit
RosterWorkCommitPublish
RosterWorkCommitServe
RosterWorkCommitContinuationProposal
RosterWorkCommitContinuationSign
RosterWorkCommitContinuationExport
RosterWorkCommitContinuedReentry
RosterWorkCommitContinuedAdmit
RosterWorkCommitContinuedServe
RosterWorkCommitPolicyExport
RosterWorkCommitInventory
RosterWorkCommitCandidateSelection
RosterWorkCommitContributionRetention
RosterWorkOther
RosterWorkReceiveResult
RosterWorkAdoptOutput
RosterClearFocus
RosterClearOwner
RosterClearPeer
RosterClearInitialStream
RosterClearContinuedStream
RosterClearReviewExpired
RosterDropLateOutput
JoinedPairFinish
JoinedRequestBegin
JoinedLeaseFinish
JoinedInventoryCheck
JoinedAuditAppend
JoinedInventoryRun
InventoryPair
InventoryRequest
InventoryLease
InventoryImport
InventoryImportRecord
InventoryScan
InventorySynchronize
InventoryInspect
InventoryDisplay
InventoryFinish
CandidateRun
CandidatePair
CandidateRequest
CandidateLease
CandidateExclusions
CandidateSelect
CandidateDisplay
CandidateRetain
CandidateAttach
FullOriginalPolicy
RetainedPredecessor
RetainedMaterial
RetainedEconomics
RetainedInvocation
RetainedRuntime
RetainedProvider
RetainedTls
RetainedWitness
RetainedPolicyRead
RetainedPolicyMatch
RetainedSelectionFiles
ContinuedPredecessor
ContinuedObservation
ContinuedOriginal
ContinuedWait
ContinuedPrepare
Bootstrap
Session
PublicRefusal
PaymentReceiver
AgreementInput
AgreementNative
WitnessSetup
WitnessOrigin
SignerStart
BirthExport
BirthRead
BirthEnroll
BirthHistory
BirthAcknowledge
BirthDistinct
SinglePrepare
SingleOpen
SinglePair
SingleSubmit
SingleExport
SingleWitness
SinglePublicationPrepare
SingleHistory
SinglePublicationOpen
SinglePublicationPair
SingleFinish
SingleClose
RosterPrepare
RosterOpen
RosterPair
RosterSubmit
RosterExport
RosterWitness
RosterPublicationPrepare
RosterHistory
RosterPublicationOpen
RosterPublicationPair
RosterFinish
RosterClose
MetadataCheck
FinancialRefusal
EndInvariant
SignerCreate
SignerExportBirth
SignerAcknowledge
SignerOpenSingleIntent
SignerPollSingleIntent
SignerExportSingle
SignerOpenSinglePublication
SignerPollSinglePublication
SignerCloseSinglePublication
SignerOpenRosterIntent
SignerPollRosterIntent
SignerExportRoster
SignerOpenRosterPublication
SignerPollRosterPublication
SignerCloseRosterPublication
SignerOpenContinuationIntent
SignerPollContinuationIntent
SignerOpenContinuedPublication
SignerPollContinuedPublication
SignerCloseContinuedPublication
SignerExportOriginalFullPlan
SignerOpenCommonContextRead
SignerPollCommonContextRead
SignerParkCommonContextCompletion
SignerPeerMetadata
SignerNativeEntry
SignerEndpoint
SignerProvider
SignerDeadline
SignerSingleController
ObservedInputs
ObservedRetainedPredecessor
ObservedAssemble
ObservedCandidateReview
ObservedPlanExport
ObservedPlanSign
ObservedPlanRead
ObservedPlanAuthenticate
ObservedPlanWitness
ObservedContinuation
ObservedOwnerSplit
ObservedReadPrepare
ObservedReadHistory
ObservedReadOpen
ObservedReadPair
ObservedReadFinish
ObservedReadPark
ObservedBarrier
ObservedProviderDrain
ConstructedPredecessor
ConstructedDisclosure
ConstructedWitnessOriginal
ConstructedWitnessGrant
ConstructedWitnessScope
ConstructedPendingFile
ConstructedPendingReview
ConstructedSignerOpen
ConstructedConsume
ConstructedSignerPark
ConstructedServerSeal
ConstructedCheckpoint
ConstructedSavedOriginal
ConstructedInvariant
ConstructedProviderDrain
SignerOpenOriginalCompletion
SignerPollOriginalCompletion
ProvedConstructionDrain
ProvedOriginalJob
ProvedOriginalCorrelation
ProvedHostPublic
ProvedWitnessKey
ProvedNamedOpen
ProvedNamedPair
ProvedNamedStatus
ProvedNamedRecords
ProvedNamedProfile
ProvedNativePins
ProvedCarrierPrepare
ProvedCarrierExport
ProvedCarrierRecover
ProvedCarrierRetained
ProvedCarrierInvariant
SignerOpenOriginalNamed
SignerPollOriginalNamed
SignerRetainOriginalProfile
SignerNamedEnrollmentExport
SignerNamedInstalledMetadata
SignerNamedVerifierArm
SignerNamedVerifierStart
SignerNamedVerifierPoll
SignerNamedAssertionExport
SignerNamedOriginalImport
SignerNamedOriginalSubmit
SignerNamedOriginalSign
SignerNamedHostServing
FullPaymentPredecessor
FullEnrollmentExport
FullEnrollmentInstall
FullArtifactsInstall
FullInstalledMetadata
FullVerifierRequest
FullAssertion
FullOriginalImport
FullAdmission
FullSignatureReturn
FullHistory
FullReturnIntake
FullMerge
FullCurrentDispatch
FullRecipientReceipt
SingleAccountUnlock
SingleRetainedRead
SingleAcquireState
SingleAttemptedSource
SingleAttemptsRead
SingleRetainedReopen
SinglePreacquire
SingleReference
SingleAccountId
SingleAudit
SingleEndpointCreate
SingleDirectoryOpen
SingleIpcBind
SingleEndpointPublish
SingleWorkOpen
SingleWorkPrepareIntent
SingleWorkPrepareSignature
SingleWorkPrepareExport
SingleWorkPrepareReentry
SingleWorkPrepareWitness
SingleWorkPrepareAcquire
SingleWorkPrepareActivate
SingleWorkPreparePublication
SingleWorkPrepareServe
SingleWorkCommitPair
SingleWorkCommitRetain
SingleWorkCommitSignature
SingleWorkCommitExport
SingleWorkCommitReentry
SingleWorkCommitWitness
SingleWorkCommitAcquire
SingleWorkCommitActivate
SingleWorkCommitAdmission
SingleWorkCommitPublication
SingleWorkCommitServe
SingleWorkRetryAcquire
SingleWorkRetryActivate
SingleWorkRetryAdmission
SingleWorkOther
SingleWorkAdoptOutput
PristineOriginalHistory
PristineProspectiveScope
PristineSignerDrain
PristineHostRevoke
PristineOriginalPreservation
PristineCustodyHandoff
PristineSetupRoot
PristineOriginalCutoff
PristinePredecessorProcess
PristineCustodyValidation
PristineOriginalAudit
""".split())
SETUP_OUTCOMES = frozenset("""
AuthorityIoTimedOut
AuthorityIoWouldBlock
AuthorityIoInterrupted
AuthorityIoUnexpectedEof
AuthorityIoWriteZero
AuthorityIoConnectionAborted
AuthorityIoConnectionRefused
AuthorityIoConnectionReset
AuthorityIoBrokenPipe
AuthorityIoNotConnected
AuthorityIoPermissionDenied
AuthorityIoInvalidData
AuthorityIoInvalidInput
AuthorityIoOther
JournalExpired
JournalPermission
JournalOther
ConstructionInvalid
ConstructionBinding
ConstructionStale
ConstructionStorage
ConstructionSync
PredicateDenied
ExactPermission
ExactLineage
ExactBinding
ExactStorage
ExactRecoveryRequired
ExactStateChanged
ExactProfileChanged
ExactBudget
ExactRoster
EngineDurableProposalConflict
EngineDurableProfileUnavailable
EngineDisclosureUnknown
EngineDisclosureDenied
EngineDurableConstructionUnavailable
EngineDurableProposalRecoveryRequired
EngineMissingEvidence
EngineInvalidTerms
EngineUnsupportedCapability
EngineDebitCapExceeded
EnginePermissionDenied
EngineInternalError
EngineAccessDenied
EngineCandidateVerificationFailed
EngineIdempotencyConflict
EngineInvalidRequest
EngineInvalidTransition
EngineLiveAuthorizationExists
EngineManualConstructionDenied
EngineNotFound
EngineRecoveryRequired
EngineResourceExhausted
EngineRetainedObservationUnavailable
EngineRevisionConflict
EngineStorageProtectionRequired
EngineStorageUnavailable
EngineUnclassified
JobConsentDenied
JobIdempotencyConflict
JobInvalidRequest
JobNotFound
JobRecoveryRequired
JobResourceExhausted
JobStateConflict
JobStorage
JobUnsupportedSchema
JobVerificationFailed
ProtocolActionMapping
ProtocolBuilderInput
ProtocolBuilderOutput
ProtocolContext
ProtocolContribution
ProtocolDisclosure
ProtocolFee
ProtocolFinalize
ProtocolInput
ProtocolManifest
ProtocolOutput
ProtocolPczt
ProtocolUnclassified
StoreAlreadyExists
StoreBudgetExceeded
StoreDatabase
StoreEncoding
StoreFile
StoreIdempotencyConflict
StoreInputReserved
StoreInvalidInput
StoreInvalidTransition
StoreLiveAuthorizationExists
StoreNotFound
StorePoisoned
StoreRecoveryRequired
StoreResourceExhausted
StoreRevisionConflict
StoreStorageSecurity
StoreUnsupportedSchema
StoreWriterEpochMismatch
BridgeBinding
BridgeConflict
BridgeMissing
BridgeUncertain
BridgeLimit
BridgePermission
BridgeRecoveryRequired
BridgeCompleteOriginRecoveryUnavailable
BridgeVerification
BridgeSignerOriginUnavailable
BridgeJournal
BridgeAuthority
BridgeWallet
BridgeIpc
AuthorityInvalidBinding
AuthorityPermission
AuthorityStaleHead
AuthorityConflict
AuthorityInactive
AuthorityRecoveryRequired
AuthorityExpired
AuthorityPolicyDenied
AuthorityBudgetExceeded
AuthorityInputReserved
AuthorityObligationReserved
AuthorityLimit
AuthorityStorage
AuthorityCorruptHistory
AuthorityPermanentStopUnavailable
AuthorityOfflineHistoryUnsupported
AuthorityConstructionHistoryUnsupported
AuthorityUnsupportedVersion
AuthorityAuthentication
AuthorityUncertain
AuthorityResolutionUnavailable
AuthoritySessionRequired
AuthoritySessionPending
OriginPermanentStopUnavailable
OriginRetirementEvidenceUnavailable
OriginSignerOriginUnavailable
OriginPeerLifetimeUnavailable
OriginAuthentication
OriginBinding
OriginConflict
OriginPermission
OriginInvalidData
OriginLocked
OriginCrypto
OriginIpc
OriginLimit
OriginIoTimedOut
OriginIoWouldBlock
OriginIoUnexpectedEof
OriginIoBrokenPipe
OriginIoConnectionReset
OriginIoConnectionAborted
OriginIoNotConnected
OriginIoInterrupted
OriginIoPermissionDenied
OriginIoOther
OriginFrameUnclassified
OriginFrameDeadline
OriginFrameEof
OriginFrameCredentialsMissing
OriginFrameCredentialsMismatch
OriginFrameAncillaryRejected
OriginFrameTruncated
OriginFramePeerNotLive
OriginFrameCurrentCheck
OriginFrameIo
OriginFrameLimit
OriginFrameInvalidFrame
OriginFrameInvalidBudget
ImportFreshOwnerRequired
ImportBinding
ImportIncomplete
ImportStorage
SyncAccessDenied
SyncInvalidRequest
SyncInterrupted
SyncReconciliationRequired
SyncInvalidResponse
SyncResourceLimit
SyncNoCurrentObservation
WalletStorage
WalletAccountScope
WalletAccountMismatch
WalletIncompleteSync
WalletUnsupportedProfile
WalletChainMismatch
WalletInsufficientFunds
WalletInvalidRequest
WalletMissingWitness
WalletInvalidNote
WalletScan
WalletTransport
ChainInvalidConfiguration
ChainWrongNetwork
ChainUnsupportedProxyConfiguration
ChainWrongBranch
ChainStaleChain
ChainContradictoryChain
ChainTimeout
ChainTransportUnavailable
ChainObservationInterrupted
ChainMissingAncestryEvidence
ChainNotObserved
ChainResourceLimit
ChainMalformedEvidence
ChainUnsupportedCapability
ChainBackendFailure
ChainClockUnavailable
ChainIdempotencyConflict
ChainJournalFailure
ChainSubmissionNotAuthorized
ChainSubmissionExpiryMargin
ChainObligationConflict
ChainSubmissionOutcomeUnrecorded
ChainSubmissionRetentionUncertain
RecoveryAccessDenied
RecoveryUnsupportedAccountComponents
RecoveryIncompleteScan
RecoveryKnownFundsRemain
RecoveryAdditionalEvidenceRequired
HostPlatform
HostTerminal
HostPermission
HostLocked
HostInvalid
HostAuthentication
HostStorage
HostQuarantined
HostUnsupported
HostReceipt
HostRecoverySemantic
HostRecoveryBackupUnsupported
HostRecoveryFinancialUnsupported
HostCompleteOriginRecoveryUnavailable
HostHistoricalExportIncomplete
HostGenerationArchiveIncomplete
SignerUnavailable
SignerPeerLifetimeUnavailable
SignerIo
SignerAuthentication
SignerInvalidData
SignerCrypto
SignerLocked
SignerBackupRequired
SignerRecoveryRequired
SignerAlreadyOpen
SignerReviewMismatch
SignerVerification
SignerUncertain
SignerConsentJournal
SignerStore
WorkerFailure
""".split())

MODES = frozenset(('smoke', 'fixture'))
CASES = ('cancel', 'blur', 'append')
STAGES = frozenset(('root', 'image', 'setup', 'custody', 'identity', 'pin', 'display',
                    'input', 'prepare', 'cancel', 'blur', 'append', 'audit', 'drain',
                    'evidence', 'lifecycle'))
CODES = frozenset('''
internal invalid_json invalid_record duplicate_key output_limit original_deadline
phase_deadline root_identity root_caps root_thread root_dumpable manifest
image_directory image_file image_hash passwd_base passwd_path passwd_home
passwd_owner pin_directory pin_file fixture_tmpfs setup_process setup_status
setup_output setup_count setup_source setup_cleanup custody_packet custody_rights
custody_credentials custody_identity custody_path custody_ack cutoff_mismatch
runtime_identity runtime_caps runtime_groups runtime_thread runtime_dumpable
namespace_not_empty display_start display_status display_protocol display_binding
display_geometry display_frame display_deadline input_widget input_disabled
input_bounds input_text input_budget input_phase source_prepare source_failure
source_digest source_currentness source_paint source_clear blur_missing
refocus_missing reactivation native_arm native_admit ready_binding effect_binding
owner_tls owner_response uncertain_effect unexpected_effect original_request
record_file record_count record_schema record_sequence record_role record_graph
record_parent record_deadline record_incomplete record_overflow evidence_order
worker_join disposal driver_join product_status product_deadline owned_reap
adopted_child forced_cleanup history_audit history_count history_identity
history_prefix history_effect cleanup_failed integration_not_frozen
'''.split())
DELIVERY_STAGES = frozenset('''
InputValidation RequestDecode EndpointValidation ServerCertificateRead
ServerCertificateValidation TrustedClientRootRead ServerPrivateKeyRead TlsConfiguration
ProtectedNamespaceOpen ListenerBind ListenerConfiguration PreparedSourceCurrentness
ReviewClock ReviewFacts ArmCurrentness TlsAccept TlsHandshake TlsPeerIdentity
TlsPreparation TlsReadyWrite TlsRequest FirstPreflight PreflightRollback FinalAdmitWait
SecondPreflight FinalCurrentness JournalAppend JournalCommit CommitRollback TlsResponse
'''.split())
DELIVERY_CLASSES = frozenset('''
InvalidBinding Permission StaleHead Conflict Inactive RecoveryRequired Expired
PolicyDenied BudgetExceeded InputReserved ObligationReserved Limit Storage
CorruptHistory PermanentStopUnavailable OfflineHistoryUnsupported
ConstructionHistoryUnsupported UnsupportedVersion Authentication Uncertain
ResolutionUnavailable SessionRequired SessionPending
'''.split())
FAILURE_KEYS = frozenset(('schema_version', 'mode', 'case', 'stage', 'code',
                          'source_boundary', 'source_outcome', 'delivery_stage',
                          'delivery_class'))
SMOKE_KEYS = frozenset(('name', 'product_exit', 'surface_bound', 'frame_observed',
                       'natural_tree_drain'))
FIXTURE_BOOL_KEYS = frozenset(('source_prepared', 'source_paint_correlated',
    'source_locally_cleared', 'worker_joined_before_disposed', 'driver_joined',
    'natural_tree_drain', 'original_request_retained', 'original_cutoff_retained'))
FIXTURE_COUNT_KEYS = frozenset(('owned_roles', 'owned_reaps',
    'original_account_histories', 'target_events', 'unchanged_non_target_histories',
    'exact_retained_request_appends', 'native_arm_count', 'native_admit_count',
    'w_final_admit_count', 'authenticated_committed_count'))
FIXTURE_KEYS = FIXTURE_BOOL_KEYS | FIXTURE_COUNT_KEYS | frozenset((
    'name', 'product_exit', 'focus_out', 'refocused', 'no_reactivation'))


class Rejected(Exception):
    def __init__(self, code):
        self.code = code if code in CODES else 'invalid_record'
        super().__init__(self.code)


def require(ok, code='invalid_record'):
    if not ok:
        raise Rejected(code)


def number(value, low, high):
    return type(value) is int and low <= value <= high


def _pairs(items):
    result = {}
    for key, value in items:
        require(key not in result, 'duplicate_key')
        result[key] = value
    return result


def loads(raw, limit=8192):
    require(type(raw) in (str, bytes) and type(limit) is int and 0 < limit <= 4 * 1024 * 1024,
            'invalid_json')
    try:
        encoded = raw.encode('utf-8') if type(raw) is str else raw
        require(0 < len(encoded) <= limit, 'output_limit')
        return json.loads(encoded, object_pairs_hook=_pairs,
                          parse_constant=lambda _: (_ for _ in ()).throw(Rejected('invalid_json')))
    except Rejected:
        raise
    except (ValueError, UnicodeError, TypeError, RecursionError):
        raise Rejected('invalid_json') from None


def validate_failure(value, mode):
    require(mode in MODES and type(value) is dict and set(value) == FAILURE_KEYS)
    require(type(value['schema_version']) is int and value['schema_version'] == 1 and
            value['mode'] == mode and type(value['stage']) is str and value['stage'] in STAGES and
            type(value['code']) is str and value['code'] in CODES)
    require(value['case'] in ((None, 'smoke') if mode == 'smoke' else (None, *CASES)))
    boundary, outcome = value['source_boundary'], value['source_outcome']
    require((boundary is None and outcome is None) or
            (type(boundary) is str and boundary in SETUP_BOUNDARIES and
             type(outcome) is str and outcome in SETUP_OUTCOMES))
    stage, cls = value['delivery_stage'], value['delivery_class']
    require((stage is None and cls is None) or
            (type(stage) is str and stage in DELIVERY_STAGES and
             type(cls) is str and cls in DELIVERY_CLASSES))
    # An exact setup operation and an exact product operation are different
    # causal observations. Never merge unrelated pairs into one first failure.
    require(boundary is None or stage is None)
    require(len(json.dumps(value, separators=(',', ':')).encode('ascii')) <= 1024)
    return value


def failure(mode, stage, code, case=None, *, source_boundary=None,
            source_outcome=None, delivery_stage=None, delivery_class=None):
    value = dict(schema_version=1, mode=mode, case=case, stage=stage, code=code,
                 source_boundary=source_boundary, source_outcome=source_outcome,
                 delivery_stage=delivery_stage, delivery_class=delivery_class)
    return validate_failure(value, mode)


def validate_case(value, mode, expected):
    require(type(value) is dict and value.get('name') == expected)
    if mode == 'smoke':
        require(set(value) == SMOKE_KEYS and number(value['product_exit'], 0, 0))
        require(all(value[name] is True for name in SMOKE_KEYS - {'name', 'product_exit'}))
        return value
    require(set(value) == FIXTURE_KEYS and number(value['product_exit'], 0, 0))
    require(all(value[name] is True for name in FIXTURE_BOOL_KEYS))
    for name, exact in (('owned_roles', 17), ('owned_reaps', 16),
                        ('original_account_histories', 3), ('unchanged_non_target_histories', 2)):
        require(number(value[name], exact, exact))
    positive = int(expected == 'append')
    require(number(value['target_events'], 4 + positive, 4 + positive))
    for name in ('exact_retained_request_appends', 'native_arm_count', 'native_admit_count',
                 'w_final_admit_count', 'authenticated_committed_count'):
        require(number(value[name], positive, positive))
    require(value['focus_out'] is (expected == 'blur') and
            value['refocused'] is (expected == 'blur') and
            value['no_reactivation'] is True)
    return value


def validate_runtime_result(value, mode):
    require(mode in MODES and type(value) is dict and set(value) == {
        'schema_version', 'mode', 'outcome', 'first_failure', 'setup_elapsed_ms',
        'cases', 'natural_empty'})
    require(type(value['schema_version']) is int and value['schema_version'] == 1 and
            value['mode'] == mode and value['outcome'] in ('passed', 'error'))
    require((value['setup_elapsed_ms'] is None or
             number(value['setup_elapsed_ms'], 0, (1 << 63) - 1)) and
            type(value['natural_empty']) is bool and type(value['cases']) is list)
    expected = ('smoke',) if mode == 'smoke' else CASES
    require(len(value['cases']) <= len(expected))
    for case, name in zip(value['cases'], expected):
        validate_case(case, mode, name)
    if value['outcome'] == 'passed':
        require(value['first_failure'] is None and value['natural_empty'] is True and
                number(value['setup_elapsed_ms'], 0, 900000) and
                len(value['cases']) == len(expected))
    else:
        validate_failure(value['first_failure'], mode)
    require(len(json.dumps(value, separators=(',', ':')).encode('ascii')) <= 8192, 'output_limit')
    return value

# Private evidence grammar. These helpers do not perform I/O, mint authority,
# authenticate a peer, or turn observer records into an independent audit. The
# collector must retain its actual Popen identity and securely read bounded,
# owned, no-follow, single-link evidence files before calling this module.
_OBSERVER_C = 'Coordinator'
_OBSERVER_W = 'Owner1V3DeliveryAdmission'
_OBSERVER_ROLES = frozenset('''Coordinator Host Signer1 Signer2
Owner1BootstrapHistory Owner1V3DeliveryAdmission Owner1DeliveryAuditHistory
Owner1FinancialReadHistory Owner1FinancialContinuationAdmission Owner1FinancialSigning
Owner2BootstrapHistory Owner2V3DeliveryAdmission Owner2DeliveryAuditHistory
Owner2FinancialReadHistory Owner2FinancialContinuationAdmission Owner2FinancialSigning
CompletedPair'''.split())
_OBSERVER_CHILDREN = {
    role: (frozenset(('Signer1', 'Signer2')) if role == 'Host' else
           _OBSERVER_ROLES - {'Coordinator', 'Signer1', 'Signer2'} if role == 'Coordinator'
           else frozenset()) for role in _OBSERVER_ROLES
}
_OBSERVER_FIELDS = frozenset(('version', 'sequence', 'role', 'pid', 'ppid',
                             'original_parent_pid', 'elapsed_ms', 'event', 'detail'))
_OBSERVER_PHASES = frozenset(('Selecting', 'Preparing', 'Reading', 'Acknowledging',
                             'Armed', 'InFlight', 'Revoked', 'Finished'))
_OBSERVER_WIDGETS = frozenset('''Endpoint ServerName WitnessId ServerCertificateDigest
NetworkProfile AccountId StorageKeyPath ServerCertificatePath ServerPrivateKeyPath
ClientRootPath OwnerCertificate Request Prepare Review Continue Acknowledge Arm Cancel Close'''.split())
_OBSERVER_SNAPSHOT = frozenset(('frame', 'pass', 'pixels_per_point', 'phase', 'viewport',
    'presentation_digest', 'focused', 'raw_blur', 'revoked', 'read_to_end', 'continued',
    'acknowledged', 'widgets'))
_OBSERVER_READY = frozenset(('presentation_digest', 'effect_commitment', 'request_commitment',
    'source_commitment', 'owner_certificate_digest', 'expected_head_sequence',
    'expected_head_digest', 'preparation_nonce', 'accepted_at_ms', 'accepted_tls_expires_at_ms'))
_OBSERVER_DIGEST_READY = _OBSERVER_READY - {'expected_head_sequence', 'accepted_at_ms',
                                          'accepted_tls_expires_at_ms'}
_OBSERVER_C_TO_W = frozenset(('Prepare', 'Arm', 'Admit', 'Cancel'))
_OBSERVER_W_TO_C = frozenset(('Review', 'Ready', 'Outcome', 'FirstFailure',
                             'PreparationFailed', 'Disposed'))


def _closed(value, keys, code='record_schema'):
    require(type(value) is dict and set(value) == set(keys), code)


def _uint(value, bits=64, code='record_schema'):
    require(number(value, 0, (1 << bits) - 1), code)


def _digest(value, optional=False, code='record_schema'):
    require((optional and value is None) or
            (type(value) is str and len(value) == 64 and
             all(c in '0123456789abcdef' for c in value)), code)


def _boolean(value, code='record_schema'):
    require(type(value) is bool, code)


def _rect(value):
    import math
    _closed(value, ('left', 'top', 'right', 'bottom'))
    require(all(type(n) in (int, float) and abs(n) <= 16384 and math.isfinite(n)
                for n in value.values()), 'record_schema')
    require(value['left'] < value['right'] and value['top'] < value['bottom'], 'record_schema')


def _snapshot(value):
    import math
    _closed(value, _OBSERVER_SNAPSHOT)
    for key in ('frame', 'pass'):
        _uint(value[key])
    scale = value['pixels_per_point']
    require(type(scale) in (int, float) and 0 < scale <= 8 and math.isfinite(scale),
            'record_schema')
    require(type(value['phase']) is str and value['phase'] in _OBSERVER_PHASES, 'record_schema')
    _rect(value['viewport'])
    _digest(value['presentation_digest'], optional=True)
    for key in ('focused', 'raw_blur', 'revoked', 'read_to_end', 'continued', 'acknowledged'):
        _boolean(value[key])
    require(type(value['widgets']) is list and len(value['widgets']) <= 20, 'record_schema')
    seen = set()
    for widget in value['widgets']:
        _closed(widget, ('widget', 'rect', 'enabled'))
        name = widget['widget']
        require(type(name) is str and name in _OBSERVER_WIDGETS and name not in seen,
                'record_schema')
        seen.add(name)
        _boolean(widget['enabled'])
        _rect(widget['rect'])
        r, v = widget['rect'], value['viewport']
        require(r['left'] >= v['left'] and r['top'] >= v['top'] and
                r['right'] <= v['right'] and r['bottom'] <= v['bottom'], 'record_schema')


def _ready(value):
    _closed(value, _OBSERVER_READY)
    for key in _OBSERVER_DIGEST_READY:
        _digest(value[key])
    for key in _OBSERVER_READY - _OBSERVER_DIGEST_READY:
        _uint(value[key])
    require(0 < value['accepted_tls_expires_at_ms'] - value['accepted_at_ms'] <= 10000, 'record_deadline')


def _outcome(value):
    require(type(value) is dict and type(value.get('outcome')) is str, 'record_schema')
    kind = value['outcome']
    require(kind in ('Committed', 'KnownNoEffect', 'Uncertain'), 'record_schema')
    keys = {'outcome', 'presentation_digest', 'effect_commitment'}
    if kind == 'Committed':
        keys |= {'head_sequence', 'head_digest'}
    _closed(value, keys)
    _digest(value['presentation_digest'])
    _digest(value['effect_commitment'], optional=kind != 'Committed')
    if kind == 'Committed':
        _uint(value['head_sequence'])
        _digest(value['head_digest'])


def validate_record(value):
    """Validate exactly one frozen DeliveryObservation record; never trust it.

    Raw integer identities, rectangles and digests remain private. The returned
    value is a detached JSON copy, not a caller-mutable validated capability.
    """
    _closed(value, _OBSERVER_FIELDS)
    require(number(value['version'], 1, 1) and number(value['sequence'], 1, 512), 'record_schema')
    role, event, detail = value['role'], value['event'], value['detail']
    require(type(role) is str and role in _OBSERVER_ROLES, 'record_role')
    require(number(value['pid'], 1, (1 << 31) - 1) and
            number(value['ppid'], 0, (1 << 31) - 1) and
            number(value['original_parent_pid'], 1, (1 << 31) - 1), 'record_parent')
    _uint(value['elapsed_ms'], 32)
    require(type(event) is str, 'record_schema')
    if event == 'RetainedBindings':
        _closed(detail, ('children', 'startup_deadline_ms', 'session_deadline_ms'))
        require(number(detail['startup_deadline_ms'], 30000, 30000) and
                number(detail['session_deadline_ms'], 300000, 300000), 'record_deadline')
        require(type(detail['children']) is list and len(detail['children']) <= 14, 'record_graph')
        seen, pids = set(), set()
        for child in detail['children']:
            _closed(child, ('role', 'pid'))
            require(type(child['role']) is str and child['role'] in _OBSERVER_CHILDREN[role]
                    and child['role'] not in seen and number(child['pid'], 1, (1 << 31) - 1)
                    and child['pid'] not in pids and child['pid'] != value['pid'], 'record_graph')
            seen.add(child['role']); pids.add(child['pid'])
        require(seen == _OBSERVER_CHILDREN[role], 'record_graph')
    elif event == 'Observation':
        _closed(detail, ('observation', 'facts'))
        kind, facts = detail['observation'], detail['facts']
        require(type(kind) is str, 'record_schema')
        require(role == (_OBSERVER_W if kind == 'WorkerJoined' else _OBSERVER_C), 'record_role')
        if kind == 'WidgetSnapshot':
            _snapshot(facts)
        elif kind == 'RawInterruption':
            _closed(facts, ('blur', 'focused', 'escape', 'close'))
            for item in facts.values(): _boolean(item)
        elif kind in ('PresentationCleared', 'WorkerJoined'):
            _closed(facts, ('presentation_digest', 'admitted') if kind == 'PresentationCleared'
                    else ('presentation_digest',))
            _digest(facts['presentation_digest'], optional=True)
            if kind == 'PresentationCleared': _boolean(facts['admitted'])
        elif kind == 'DriverJoined':
            _closed(facts, ('clean',)); _boolean(facts['clean'])
        else:
            raise Rejected('record_schema')
    elif event in _OBSERVER_C_TO_W | _OBSERVER_W_TO_C:
        require(type(detail) is dict and type(detail.get('direction')) is str, 'record_schema')
        direction = detail['direction']
        if direction == 'Native':
            require(role == _OBSERVER_C and event in ('Arm', 'Admit'), 'record_role')
        else:
            require(direction in ('Sent', 'Received'), 'record_schema')
            sender = _OBSERVER_C if event in _OBSERVER_C_TO_W else _OBSERVER_W
            receiver = _OBSERVER_W if sender == _OBSERVER_C else _OBSERVER_C
            require(role == (sender if direction == 'Sent' else receiver), 'record_role')
        keys = {'direction'}
        if event == 'Review':
            keys |= {'presentation_digest', 'prepared_at_ms', 'expires_at_ms', 'monotonic_deadline_ms'}
        elif event == 'Ready': keys |= {'data', 'monotonic_deadline_ms'}
        elif event == 'Arm': keys.add('presentation_digest')
        elif event == 'Admit': keys |= {'presentation_digest', 'effect_commitment'}
        elif event in ('Outcome', 'FirstFailure'): keys.add('data')
        elif event == 'Prepare': keys.add('original_ceiling_ms')
        _closed(detail, keys)
        for key in ('presentation_digest', 'effect_commitment'):
            if key in detail: _digest(detail[key])
        if event == 'Review':
            for key in ('prepared_at_ms', 'expires_at_ms', 'monotonic_deadline_ms'): _uint(detail[key])
            require(0 < detail['expires_at_ms'] - detail['prepared_at_ms'] <= 120000, 'record_deadline')
        elif event == 'Ready':
            _ready(detail['data']); _uint(detail['monotonic_deadline_ms'])
        elif event == 'Outcome': _outcome(detail['data'])
        elif event == 'FirstFailure':
            _closed(detail['data'], ('stage', 'class'))
            require(type(detail['data']['stage']) is str and detail['data']['stage'] in DELIVERY_STAGES
                    and type(detail['data']['class']) is str and detail['data']['class'] in DELIVERY_CLASSES,
                    'record_schema')
        elif event == 'Prepare':
            if direction == 'Sent': _uint(detail['original_ceiling_ms'])
            else: require(detail['original_ceiling_ms'] is None, 'record_schema')
    elif event == 'OwnedReap':
        _closed(detail, ('child_role', 'child_pid', 'exit_code', 'signal', 'forced'))
        require(type(detail['child_role']) is str and detail['child_role'] in _OBSERVER_CHILDREN[role]
                and number(detail['child_pid'], 1, (1 << 31) - 1), 'record_graph')
        require((number(detail['exit_code'], 0, 255) and detail['signal'] is None) or
                (detail['exit_code'] is None and number(detail['signal'], 1, 127)), 'record_schema')
        _boolean(detail['forced'])
    elif event == 'RoleFinished':
        _closed(detail, ('exit_code',)); require(number(detail['exit_code'], -(1 << 31), (1 << 31) - 1), 'record_schema')
    elif event == 'EvidenceClosed':
        _closed(detail, ('complete',)); _boolean(detail['complete'])
    else:
        raise Rejected('record_schema')
    try:
        encoded = json.dumps(value, separators=(',', ':'), allow_nan=False).encode('utf-8')
    except (ValueError, TypeError, RecursionError, OverflowError):
        raise Rejected('record_schema') from None
    require(len(encoded) + 1 <= 16 * 1024, 'record_overflow')
    return loads(encoded, limit=16 * 1024)


def load_observer_files(files):
    """Parse bounded file bytes already securely collected by the inner owner.

    Blank/truncated lines, duplicate JSON fields and filename/PID mismatches are
    rejected. This does not open files or substitute for filesystem provenance.
    """
    require(type(files) is dict and 0 < len(files) <= 32, 'record_count')
    result, total = [], 0
    for name, raw in files.items():
        require(type(name) is str and 7 <= len(name) <= 16 and name.endswith('.jsonl') and name[:-6].isascii()
                and name[:-6].isdigit() and name[:-6] == str(int(name[:-6])) and int(name[:-6]) > 0,
                'record_file')
        require(type(raw) is bytes and 0 < len(raw) <= 256 * 1024, 'record_overflow')
        total += len(raw)
        require(total <= 4 * 1024 * 1024 and raw.endswith(b'\n'), 'record_overflow')
        lines = raw.splitlines(keepends=True)
        require(len(lines) <= 512, 'record_count')
        for line in lines:
            require(line.endswith(b'\n') and len(line) <= 16 * 1024, 'record_overflow')
            record = validate_record(loads(line, limit=16 * 1024))
            require(record['pid'] == int(name[:-6]), 'record_file')
            result.append(record)
            require(len(result) <= 4096, 'record_count')
    return result


def validate_trace(records, *, root_pid, root_status=None, complete=True, root_parent_pid=1):
    """Validate local order and immutable retained ownership, not wall ordering.

    A successful send is observed AFTER send(2); a peer may receive first. No
    cross-role Sent/Received timestamp ordering is asserted anywhere here.
    Partial traces are useful only for private input targeting, never a pass.
    """
    require(type(records) is list and 0 < len(records) <= 4096, 'record_count')
    require(number(root_pid, 1, (1 << 31) - 1) and number(root_parent_pid, 1, (1 << 31) - 1)
            and type(complete) is bool, 'record_parent')
    if complete: require(number(root_status, 0, 0), 'product_status')
    groups, pids, total = {}, {}, 0
    for untrusted in records:
        record = validate_record(untrusted)
        role, pid = record['role'], record['pid']
        require(pid not in pids or pids[pid] == role, 'record_graph')
        pids[pid] = role
        rows = groups.setdefault(role, [])
        require(not rows or rows[0]['pid'] == pid, 'record_graph')
        require(record['sequence'] == len(rows) + 1, 'record_sequence')
        require(not rows or record['elapsed_ms'] >= rows[-1]['elapsed_ms'], 'record_sequence')
        require(not rows or record['original_parent_pid'] == rows[0]['original_parent_pid'], 'record_parent')
        require(record['elapsed_ms'] <= 305000, 'record_deadline')
        require(not rows or rows[-1]['event'] != 'EvidenceClosed', 'record_incomplete')
        require(not rows or rows[-1]['event'] != 'RoleFinished' or record['event'] == 'EvidenceClosed',
                'record_incomplete')
        require((not rows) == (record['event'] == 'RetainedBindings'), 'record_graph')
        rows.append(record)
        total += len(json.dumps(record, separators=(',', ':')).encode('utf-8')) + 1
    require(total <= 4 * 1024 * 1024, 'record_overflow')
    require(_OBSERVER_C in groups and groups[_OBSERVER_C][0]['pid'] == root_pid, 'record_parent')
    declarations = {_OBSERVER_C: root_pid}
    for role, rows in groups.items():
        require(sum(len(json.dumps(r, separators=(',', ':')).encode('utf-8')) + 1 for r in rows)
                <= 256 * 1024, 'record_overflow')
        for child in rows[0]['detail']['children']:
            require(child['role'] not in declarations and child['pid'] not in declarations.values(), 'record_graph')
            declarations[child['role']] = child['pid']
    require(root_parent_pid not in declarations.values() and
            groups[_OBSERVER_C][0]['original_parent_pid'] == root_parent_pid, 'record_parent')
    if complete:
        require(all(r['ppid'] == root_parent_pid for r in groups[_OBSERVER_C]), 'record_parent')
    for role, rows in groups.items():
        require(declarations.get(role) == rows[0]['pid'], 'record_graph')
        parent = 'Host' if role in ('Signer1', 'Signer2') else _OBSERVER_C
        if role != _OBSERVER_C:
            require(parent in declarations and rows[0]['original_parent_pid'] == declarations[parent], 'record_parent')
            if complete:
                require(all(r['ppid'] == r['original_parent_pid'] for r in rows), 'record_parent')
        snapshots = [r for r in rows if _is_observation(r, 'WidgetSnapshot')]
        require(len(snapshots) <= 256, 'record_overflow')
        for old, new in zip(snapshots, snapshots[1:]):
            a, b = old['detail']['facts'], new['detail']['facts']
            require(b['frame'] > a['frame'] and b['pass'] > a['pass'], 'evidence_order')
        reaped = set()
        for record in rows:
            if record['event'] == 'OwnedReap':
                detail = record['detail']; child = detail['child_role']
                require(child not in reaped and declarations.get(child) == detail['child_pid'], 'owned_reap')
                reaped.add(child)
                if complete:
                    require(detail['exit_code'] == 0 and detail['signal'] is None and not detail['forced'], 'owned_reap')
            elif record['event'] == 'EvidenceClosed':
                require(record['detail']['complete'] is True and record['sequence'] >= 3 and
                        rows[record['sequence'] - 2]['event'] == 'RoleFinished', 'record_incomplete')
        if complete:
            require(len(rows) >= 3 and rows[-1]['event'] == 'EvidenceClosed' and
                    rows[-2]['event'] == 'RoleFinished', 'record_incomplete')
            require(rows[-2]['detail']['exit_code'] == 0, 'product_status')
            require(reaped == _OBSERVER_CHILDREN[role], 'owned_reap')
    if complete:
        require(set(groups) == _OBSERVER_ROLES and set(declarations) == _OBSERVER_ROLES, 'record_graph')
        require(sum(r['event'] == 'OwnedReap' for rows in groups.values() for r in rows) == 16, 'owned_reap')
    return groups


def _is_observation(record, kind):
    return record['event'] == 'Observation' and record['detail']['observation'] == kind


def latest_widget_snapshot(records, *, root_pid):
    """Return the latest detached C record, including sequence and snapshot.

    A digest/rectangle is an inert observation, not permission to click. The
    driver separately checks freshness, focus, phase and the widget's enabled
    state before genuine compositor input. A reparented C cannot be targeted.
    """
    rows = validate_trace(records, root_pid=root_pid, complete=False)[_OBSERVER_C]
    require(all(r['ppid'] == r['original_parent_pid'] for r in rows), 'record_parent')
    require(not any(r['event'] in ('RoleFinished', 'EvidenceClosed') or
                    _is_observation(r, 'DriverJoined') for r in rows), 'input_phase')
    snapshots = [r for r in rows if _is_observation(r, 'WidgetSnapshot')]
    require(bool(snapshots), 'input_widget')
    return snapshots[-1]


def _events(rows, event, direction=None):
    return [r for r in rows if r['event'] == event and
            (direction is None or r['detail'].get('direction') == direction)]


def _only(rows, event, direction=None, code='evidence_order'):
    matches = _events(rows, event, direction)
    require(len(matches) == 1, code)
    return matches[0]


def _only_observation(rows, kind, code):
    matches = [r for r in rows if _is_observation(r, kind)]
    require(len(matches) == 1, code)
    return matches[0]


def _local_before(*records, code='evidence_order'):
    require(all(a['role'] == b['role'] and a['sequence'] < b['sequence']
                for a, b in zip(records, records[1:])), code)


def _paired(c, w, event, required=True):
    sender, receiver = (c, w) if event in _OBSERVER_C_TO_W else (w, c)
    sent, received = _events(sender, event, 'Sent'), _events(receiver, event, 'Received')
    require(len(sent) == len(received) and len(sent) == int(required), 'evidence_order')
    if not required: return None, None
    left, right = dict(sent[0]['detail']), dict(received[0]['detail'])
    del left['direction']; del right['direction']
    # Receiver computes a stricter local deadline from the original bound; it
    # does not serialize the sender's local deadline. Prepare has no receiver
    # deadline field at all. Neither exception weakens the wire-data equality.
    if event in ('Review', 'Ready'):
        a, b = left.pop('monotonic_deadline_ms'), right.pop('monotonic_deadline_ms')
        # Wall expiry is on the wire; the exact sender Instant is not.
        # Independent sampling/rounding must not invent a cross-role order.
        require(0 < a <= 300000 and 0 < b <= 300000 and sent[0]['elapsed_ms'] < a and
                received[0]['elapsed_ms'] < b, 'record_deadline')
    elif event == 'Prepare':
        a, b = left.pop('original_ceiling_ms'), right.pop('original_ceiling_ms')
        require(b is None and sent[0]['elapsed_ms'] < a <= 300000 and
                a - sent[0]['elapsed_ms'] <= 120000, 'record_deadline')
    require(left == right, 'effect_binding' if event in ('Admit', 'Outcome') else 'ready_binding')
    return sent[0], received[0]


def _validate_delivery_path(groups, case):
    c, w = groups[_OBSERVER_C], groups[_OBSERVER_W]
    positive = case == 'append'
    pairs = {name: _paired(c, w, name, name not in ('Arm', 'Admit', 'Ready') or positive)
             for name in ('Prepare', 'Review', 'Arm', 'Ready', 'Admit', 'Cancel', 'Outcome', 'Disposed')}
    _paired(c, w, 'PreparationFailed', False)
    # FirstFailure is a closed diagnostic, not proof of an uncertain effect.
    failure_count = len(_events(w, 'FirstFailure', 'Sent'))
    require(failure_count <= 1, 'evidence_order')
    failure_pair = _paired(c, w, 'FirstFailure', bool(failure_count))
    prepare_c, prepare_w = pairs['Prepare']
    review_w, review_c = pairs['Review']
    cancel_c, cancel_w = pairs['Cancel']
    outcome_w, outcome_c = pairs['Outcome']
    disposed_w, disposed_c = pairs['Disposed']
    digest = review_c['detail']['presentation_digest']
    ceiling = prepare_c['detail']['original_ceiling_ms']
    require(review_c['detail']['monotonic_deadline_ms'] <= ceiling, 'record_deadline')
    _local_before(prepare_c, review_c, outcome_c, disposed_c)
    _local_before(prepare_w, review_w, outcome_w, disposed_w)
    joined = _only_observation(w, 'WorkerJoined', 'worker_join')
    cleared = _only_observation(c, 'PresentationCleared', 'source_clear')
    driver = _only_observation(c, 'DriverJoined', 'driver_join')
    require(joined['detail']['facts']['presentation_digest'] == digest, 'worker_join')
    require(cleared['detail']['facts'] == {'presentation_digest': digest, 'admitted': positive}, 'source_clear')
    require(driver['detail']['facts']['clean'] is True, 'driver_join')
    _local_before(review_w, joined, outcome_w, disposed_w, code='worker_join')
    _local_before(disposed_c, driver, c[-2], code='driver_join')
    _local_before(prepare_c, cancel_c, driver)
    _local_before(prepare_w, cancel_w, w[-2])
    for reaped in _events(c, 'OwnedReap'):
        _local_before(disposed_c, reaped, driver, code='owned_reap')
    if failure_count:
        _local_before(joined, failure_pair[0], outcome_w)
        _local_before(prepare_c, failure_pair[1], outcome_c)
    snapshots = [r for r in c if _is_observation(r, 'WidgetSnapshot')]
    source = [r for r in snapshots if review_c['sequence'] < r['sequence'] < cleared['sequence']
              and r['detail']['facts']['presentation_digest'] == digest
              and r['detail']['facts']['phase'] in ('Reading', 'Acknowledging')
              and r['detail']['facts']['focused'] and not r['detail']['facts']['revoked']
              and any(x['widget'] == 'Review' for x in r['detail']['facts']['widgets'])]
    require(bool(source), 'source_prepare')
    later = [r for r in snapshots if r['sequence'] > cleared['sequence']]
    require(bool(later), 'source_clear')
    # A cancel click can clear state after that frame's old source was drawn.
    # Its one snapshot may therefore carry old painted metadata but revoked=true.
    # That is not reactivation. A later clear-state paint is required separately.
    require(all(r['detail']['facts']['revoked'] and
                r['detail']['facts']['phase'] not in ('Selecting', 'Preparing', 'Armed')
                for r in later), 'reactivation')
    stale_paints = [r for r in later if r['detail']['facts']['presentation_digest'] is not None]
    require(len(stale_paints) <= 1 and (not stale_paints or stale_paints[0] is later[0]) and
            all(r['detail']['facts']['presentation_digest'] == digest for r in stale_paints), 'reactivation')
    for record in later:
        require(not any(x['enabled'] and x['widget'] in ('Prepare', 'Continue', 'Acknowledge', 'Arm')
                        for x in record['detail']['facts']['widgets']) or
                record['detail']['facts']['presentation_digest'] == digest, 'reactivation')
    terminal = outcome_c['detail']['data']
    require(terminal['presentation_digest'] == digest, 'effect_binding')
    arm_native = _events(c, 'Arm', 'Native')
    admit_native = _events(c, 'Admit', 'Native')
    require(len(arm_native) == int(positive), 'native_arm')
    require(len(admit_native) == int(positive), 'native_admit')
    if positive:
        arm_c, arm_w = pairs['Arm']; ready_w, ready_c = pairs['Ready']
        admit_c, admit_w = pairs['Admit']; ready = ready_c['detail']['data']
        require(ready['presentation_digest'] == digest and
                ready['expected_head_sequence'] == 4, 'ready_binding')
        require(arm_native[0]['detail']['presentation_digest'] == digest and
                arm_c['detail']['presentation_digest'] == digest, 'native_arm')
        binding = {'presentation_digest': digest, 'effect_commitment': ready['effect_commitment']}
        require({k: v for k, v in admit_native[0]['detail'].items() if k != 'direction'} == binding and
                {k: v for k, v in admit_c['detail'].items() if k != 'direction'} == binding, 'effect_binding')
        require(ready_c['detail']['monotonic_deadline_ms'] <= review_c['detail']['monotonic_deadline_ms']
                and ready_w['detail']['monotonic_deadline_ms'] <= review_w['detail']['monotonic_deadline_ms']
                and review_c['detail']['prepared_at_ms'] <= ready['accepted_at_ms'] <
                ready['accepted_tls_expires_at_ms'] and
                ready['accepted_at_ms'] < review_c['detail']['expires_at_ms'] and
                ready['accepted_tls_expires_at_ms'] - ready['accepted_at_ms'] <= 10000, 'record_deadline')
        require(arm_native[0]['elapsed_ms'] < review_c['detail']['monotonic_deadline_ms'] and
                admit_native[0]['elapsed_ms'] < ready_c['detail']['monotonic_deadline_ms'] and
                arm_w['elapsed_ms'] < review_w['detail']['monotonic_deadline_ms'] and
                admit_w['elapsed_ms'] < ready_w['detail']['monotonic_deadline_ms'], 'record_deadline')
        _local_before(review_c, arm_native[0], arm_c, ready_c, admit_native[0], admit_c, outcome_c)
        _local_before(review_w, arm_w, ready_w, admit_w, joined)
        acknowledgments = [r for r in source if r['sequence'] < arm_native[0]['sequence'] and
            r['detail']['facts']['phase'] == 'Acknowledging' and r['detail']['facts']['read_to_end'] and
            r['detail']['facts']['continued'] and r['detail']['facts']['acknowledged']]
        require(bool(acknowledgments), 'native_arm')
        require(terminal['outcome'] == 'Committed', 'uncertain_effect' if terminal['outcome'] == 'Uncertain'
                else 'unexpected_effect')
        require(terminal['effect_commitment'] == ready['effect_commitment'] and
                terminal['head_sequence'] == 5, 'effect_binding')
    else:
        ready = None
        # Native revoke is shared before the synchronous clear. The driver
        # may send Cancel before the clear observation. Do not invent a
        # cross-thread happens-before relation from post-send timestamps.
        _local_before(review_c, cleared, driver, code='source_clear')
        _local_before(review_c, cancel_c, outcome_c)
        _local_before(review_w, cancel_w, joined, code='worker_join')
        require(terminal['outcome'] == 'KnownNoEffect' and terminal['effect_commitment'] is None,
                'uncertain_effect' if terminal['outcome'] == 'Uncertain' else 'unexpected_effect')
    blur = [r for r in c if _is_observation(r, 'RawInterruption') and
            r['detail']['facts']['blur'] and not r['detail']['facts']['focused']]
    if case == 'blur':
        require(any(review_c['sequence'] < r['sequence'] < cleared['sequence'] for r in blur), 'blur_missing')
        refocused = [r for r in later if r['detail']['facts']['focused'] and
                     r['detail']['facts']['presentation_digest'] is None and
                     r['detail']['facts']['phase'] in ('Revoked', 'Finished')]
        require(bool(refocused), 'refocus_missing')
    else:
        require(not any(r['sequence'] < cleared['sequence'] for r in blur), 'blur_missing')
    return dict(c=c, w=w, digest=digest, source=source, cleared=cleared,
                ready=ready, terminal=terminal, pairs=pairs)


def _receipt(value, code='source_paint'):
    _closed(value, ('sequence', 'commit', 'frame', 'input_sequence'), code)
    require(number(value['sequence'], 1, 65536) and number(value['commit'], 0, 262144) and
            number(value['frame'], 0, 262144) and
            number(value['input_sequence'], 0, value['sequence']), code)


def _audit_facts(value, case, root_pid, root_status):
    _closed(value, ('result', 'original', 'current', 'drain', 'audited_ns'), 'history_audit')
    expected = dict(version=1, kind='pristine_delivery_originals_audit_v1',
        expectation='one_exact_append' if case == 'append' else 'pristine',
        original_account_histories=3, original_main_journals=3, target_original_prefix_events=4,
        target_current_events=5 if case == 'append' else 4, unchanged_non_target_histories=2,
        exact_retained_request_appends=int(case == 'append'), original_source_commitments_match=True,
        no_successor_effect=True)
    _closed(value['result'], expected, 'history_audit')
    require(all(type(value['result'][k]) is type(v) and value['result'][k] == v
                for k, v in expected.items()), 'history_audit')
    for name in ('original', 'current'):
        _closed(value[name], ('descriptor_digest', 'request_commitment', 'cutoff_ns',
            'account_id', 'operation_id', 'expected_head', 'owner_certificate_digest'), 'original_request')
        _digest(value[name]['descriptor_digest'], code='original_request')
        _digest(value[name]['request_commitment'], code='original_request')
        _digest(value[name]['account_id'], code='original_request')
        _digest(value[name]['owner_certificate_digest'], code='original_request')
        _operation_id(value[name]['operation_id'])
        _head(value[name]['expected_head'], expected=4)
        require(number(value[name]['cutoff_ns'], 1, (1 << 64) - 1), 'original_deadline')
    require(value['original']['cutoff_ns'] == value['current']['cutoff_ns'], 'original_deadline')
    require(value['original'] == value['current'], 'original_request')
    drain = value['drain']
    _closed(drain, ('root_pid', 'exit_status', 'remaining_pids', 'remaining_process_groups', 'observed_ns'), 'owned_reap')
    require(number(drain['root_pid'], root_pid, root_pid) and
            number(drain['exit_status'], root_status, root_status), 'product_status')
    require(type(drain['remaining_pids']) is list and drain['remaining_pids'] == [] and
            type(drain['remaining_process_groups']) is list and drain['remaining_process_groups'] == [], 'adopted_child')
    _uint(drain['observed_ns']); _uint(value['audited_ns'])
    require(0 < drain['observed_ns'] < value['audited_ns'] <= value['original']['cutoff_ns'], 'original_deadline')
    return value


def _paint_capture(value, rows, digest, *, clear, clear_sequence):
    _closed(value, ('snapshot_sequence', 'frame', 'pass', 'presentation_digest', 'snapshot_read_ns',
        'requested_ns', 'completed_ns', 'request_receipt', 'observed_receipt',
        'region', 'region_before_digest', 'region_after_digest'), 'source_paint')
    require(number(value['snapshot_sequence'], 1, 512), 'source_paint')
    matches = [r for r in rows if r['sequence'] == value['snapshot_sequence'] and
               _is_observation(r, 'WidgetSnapshot')]
    require(len(matches) == 1, 'source_paint')
    record, snapshot = matches[0], matches[0]['detail']['facts']
    for key in ('frame', 'pass'):
        _uint(value[key]); require(value[key] == snapshot[key], 'source_paint')
    _digest(value['presentation_digest'], optional=True, code='source_paint')
    require(value['presentation_digest'] == snapshot['presentation_digest'], 'source_paint')
    if clear:
        require(record['sequence'] > clear_sequence and snapshot['presentation_digest'] is None and
                snapshot['revoked'] and snapshot['phase'] in ('Revoked', 'Finished'), 'source_clear')
        require(not any(x['enabled'] and x['widget'] in ('Prepare', 'Continue', 'Acknowledge', 'Arm')
                        for x in snapshot['widgets']), 'reactivation')
    else:
        require(record['sequence'] < clear_sequence and snapshot['presentation_digest'] == digest and
                snapshot['focused'] and not snapshot['revoked'] and
                snapshot['phase'] in ('Reading', 'Acknowledging') and
                any(x['widget'] == 'Review' for x in snapshot['widgets']), 'source_paint')
    for name in ('snapshot_read_ns', 'requested_ns', 'completed_ns'): _uint(value[name])
    require(0 < value['snapshot_read_ns'] <= value['requested_ns'] < value['completed_ns'], 'source_paint')
    before, after = value['request_receipt'], value['observed_receipt']
    _receipt(before); _receipt(after)
    # request_receipt is the module's actual FRAME-receipt floor, not the
    # previous input ACK. A later ACK alone cannot establish rendered content.
    require(after['sequence'] == before['sequence'] and after['commit'] > before['commit'] and
            after['frame'] > before['frame'] and after['input_sequence'] == before['input_sequence'], 'source_paint')
    _closed(value['region'], ('left', 'top', 'right', 'bottom'), 'source_paint')
    region = value['region']
    require(number(region['left'], 0, 1279) and number(region['right'], 1, 1280) and
            number(region['top'], 0, 799) and number(region['bottom'], 1, 800) and
            region['left'] < region['right'] and region['top'] < region['bottom'], 'source_paint')
    if not clear:
        import math
        review_rect = next(w['rect'] for w in snapshot['widgets'] if w['widget'] == 'Review')
        scale = snapshot['pixels_per_point']
        expected_region = {k: (math.floor(v * scale) if k in ('left', 'top') else math.ceil(v * scale))
                           for k, v in review_rect.items()}
        # The compositor independently rejects nonidentity/nonzero-offset
        # mappings. This is the clipped actual Review region, never a free ROI.
        require(region == expected_region, 'source_paint')
    _digest(value['region_before_digest'], code='source_paint')
    _digest(value['region_after_digest'], code='source_paint')
    require(value['region_before_digest'] != value['region_after_digest'], 'source_paint')
    return record


def _paint_facts(value, path, case, root_pid, audit):
    _closed(value, ('root_pid', 'app_id', 'artifact_digest', 'original_artifact_digest',
        'source', 'cleared', 'action', 'focus_out', 'refocus'), 'source_paint')
    require(number(value['root_pid'], root_pid, root_pid) and
            value['app_id'] == 'org.wholepact.CoordinatorDelivery', 'display_binding')
    for key in ('artifact_digest', 'original_artifact_digest'): _digest(value[key], code='display_binding')
    require(value['artifact_digest'] == value['original_artifact_digest'], 'display_binding')
    c, clear = path['c'], path['cleared']['sequence']
    source = _paint_capture(value['source'], c, path['digest'], clear=False, clear_sequence=clear)
    cleared = _paint_capture(value['cleared'], c, path['digest'], clear=True, clear_sequence=clear)
    require(source in path['source'], 'source_paint')
    require(value['cleared']['region'] == value['source']['region'] and
            value['cleared']['region_before_digest'] == value['source']['region_after_digest'], 'source_paint')
    require(value['source']['completed_ns'] < value['cleared']['snapshot_read_ns'] and
            value['cleared']['completed_ns'] < audit['drain']['observed_ns'], 'source_paint')
    action = value['action']; _receipt(action)
    require(value['source']['observed_receipt']['sequence'] < action['sequence'] <
            value['cleared']['request_receipt']['sequence'] and
            action['input_sequence'] == action['sequence'], 'source_paint')
    if case == 'blur':
        _receipt(value['focus_out'], 'blur_missing'); _receipt(value['refocus'], 'refocus_missing')
        require(value['focus_out'] == action and action['sequence'] < value['refocus']['sequence'] <
                value['cleared']['request_receipt']['sequence'] and
                value['refocus']['input_sequence'] == value['refocus']['sequence'], 'refocus_missing')
        require(cleared['detail']['facts']['focused'] is True, 'refocus_missing')
    else:
        require(value['focus_out'] is None and value['refocus'] is None, 'display_binding')
    return value


def _operation_id(value):
    require(type(value) is str and 0 < len(value) <= 128 and
            all(c in 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_.:' for c in value), 'original_request')


def _head(value, *, expected):
    _closed(value, ('sequence', 'digest'), 'effect_binding')
    require(number(value['sequence'], expected, expected), 'effect_binding')
    _digest(value['digest'], code='effect_binding')


def _owner_facts(value, path, audit, case):
    if case != 'append':
        require(value is None, 'unexpected_effect')
        return
    # This record must come ONLY from the independently launched maintained
    # same-stream owner TLS client, never from a C/W observer record. Ordinary
    # dictionaries cannot prove that provenance; real call sites must verify it.
    _closed(value, ('version', 'scope', 'outcome', 'original_monotonic_cutoff_ns',
        'preparation_nonce', 'request_commitment', 'operation_id', 'account_id',
        'expected_head', 'committed_head'), 'owner_response')
    require(number(value['version'], 1, 1) and value['scope'] == 'synthetic-witness-one-append-only'
            and value['outcome'] == 'Committed', 'owner_response')
    for key in ('preparation_nonce', 'request_commitment', 'account_id'):
        _digest(value[key], code='owner_response')
    _operation_id(value['operation_id'])
    _head(value['expected_head'], expected=4); _head(value['committed_head'], expected=5)
    original, ready, terminal = audit['original'], path['ready'], path['terminal']
    require(number(value['original_monotonic_cutoff_ns'], original['cutoff_ns'], original['cutoff_ns']),
            'original_deadline')
    require(value['request_commitment'] == original['request_commitment'] == ready['request_commitment'] and
            value['account_id'] == original['account_id'] and
            value['operation_id'] == original['operation_id'] and
            value['expected_head'] == original['expected_head'], 'original_request')
    require(value['preparation_nonce'] == ready['preparation_nonce'] and
            ready['owner_certificate_digest'] == original['owner_certificate_digest'] and
            ready['expected_head_sequence'] == original['expected_head']['sequence'] and
            ready['expected_head_digest'] == original['expected_head']['digest'], 'ready_binding')
    require(value['committed_head'] == {'sequence': terminal['head_sequence'],
                                      'digest': terminal['head_digest']}, 'effect_binding')


def delivery_first_failure(records):
    """Return actual closed diagnostic data, or None, without inventing cause.

    FirstFailure can accompany a correct KnownNoEffect outcome. It must not
    override a separately observed earlier runtime failure or imply an effect.
    """
    require(type(records) is list and len(records) <= 4096, 'record_count')
    found = []
    for record in records:
        checked = validate_record(record)
        if checked['event'] == 'FirstFailure': found.append(checked)
    require(len(found) <= 2 and len({r['role'] for r in found}) == len(found), 'evidence_order')
    if not found: return None
    data = found[0]['detail']['data']
    require(all(r['detail']['data'] == data for r in found), 'evidence_order')
    return dict(data)


def observer_failure(error, case, *, records=()):
    """Finite oracle failure. Do not replace an earlier runtime first failure.

    A typed source diagnostic is attached only for an actual source/effect
    failure, never merged into an unrelated parser, controller or cleanup error.
    """
    code = getattr(error, 'code', 'internal')
    code = code if code in CODES else 'internal'
    stage = ('drain' if code in ('worker_join', 'disposal', 'driver_join', 'product_status',
                                 'product_deadline', 'owned_reap', 'adopted_child', 'forced_cleanup', 'cleanup_failed') else
             'audit' if code.startswith('history_') else
             'display' if code.startswith('display_') or code == 'source_paint' else
             'prepare' if code in ('source_prepare', 'source_failure', 'source_digest', 'source_currentness') else
             case if code in ('blur_missing', 'refocus_missing', 'reactivation', 'source_clear',
                               'native_arm', 'native_admit', 'ready_binding', 'effect_binding',
                               'owner_tls', 'owner_response', 'uncertain_effect', 'unexpected_effect',
                               'original_request', 'original_deadline') else 'evidence')
    data = None
    if records and code in ('source_failure', 'uncertain_effect'):
        try:
            data = delivery_first_failure(records)
        except Rejected:
            pass  # The original failing code wins; malformed diagnostics do not.
    return failure('fixture', stage, code, case,
                   delivery_stage=None if data is None else data['stage'],
                   delivery_class=None if data is None else data['class'])


def project_case(records, case, *, root_pid, root_status, audit, paint, owner_client):
    """Project one synthetic case after complete independent evidence checks.

    audit must be produced by the original authenticated-history selector after
    natural drain. paint must be built by the actual bound compositor collector
    from private region pixels and FRAME-receipt barriers. owner_client must be
    the actual maintained same-stream TLS helper's result. Schemas validate and
    correlate these facts; they do not cryptographically authenticate dictionaries.
    The outer owner must preserve one fixture, original namespace/path/request,
    absolute 900s ceiling, same positive image, case order and one append maximum.
    No glyph visibility, sensitive-pixel absence, human consent, Signer financial
    authority, container removal, or product capability is claimed here.
    """
    try:
        require(type(case) is str and case in CASES, 'invalid_record')
        groups = validate_trace(records, root_pid=root_pid, root_status=root_status)
        path = _validate_delivery_path(groups, case)
        audited = _audit_facts(audit, case, root_pid, root_status)
        _paint_facts(paint, path, case, root_pid, audited)
        _owner_facts(owner_client, path, audited, case)
        positive = int(case == 'append')
        value = {key: True for key in FIXTURE_BOOL_KEYS}
        value.update(name=case, product_exit=root_status, owned_roles=len(groups), owned_reaps=16,
            original_account_histories=3, target_events=4 + positive,
            unchanged_non_target_histories=2, exact_retained_request_appends=positive,
            native_arm_count=positive, native_admit_count=positive,
            w_final_admit_count=positive, authenticated_committed_count=positive,
            focus_out=case == 'blur', refocused=case == 'blur', no_reactivation=True)
        return validate_case(value, 'fixture', case)
    except Rejected as error:
        if type(case) is str and case in CASES:
            error.failure = observer_failure(error, case, records=records)
        raise
