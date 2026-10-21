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
