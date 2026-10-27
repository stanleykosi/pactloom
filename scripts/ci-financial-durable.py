#!/usr/bin/env python3
"""Closed NativeV3 durable correctness profile; import is inert.

This is not the coordinated/rendered-UI oracle. The explicit selective recipe
uses Signer opt-level 1 and Engine opt-level 0; it never changes an authority bound.
Runtime output remains private except for the exact finite receipts below.
"""
import ctypes
import hashlib
import json
import os
import pathlib
import re
import selectors
import signal
import subprocess
import time

PROFILE = 'financial-durable-result-lifecycle-selective-v3'
GATE = b'financial-durable-v2\n'
ROLE = 'durable-lifecycle-qualification'
ARTIFACTS = (ROLE,)
MANIFEST_VERSION = 3
FEATURE_TEXT = 'durable-proposal,synthetic-born-joined-qualification'
FEATURES = ['durable-proposal','financial-runtime','manual-admission','synthetic-born-joined-qualification']
OVERRIDES = ('profile.release.package.wholepact-signer.opt-level=1',
             'profile.release.package.wholepact-engine.opt-level=0')
PREFIX = ('host::manual_enrollment::command::roster_publication_v2::sequential_construction_v3::'
          'qualification::durable_proposal_v1::delivery_admission_v2::durable_result_lifecycle_v2::')
CASES = {
    'durable-resume': PREFIX + 'original_two_owner_durable_results_resume_unfinished_counterpart_v2',
    'durable-started': PREFIX + 'original_financial_started_without_result_remains_uncertain_after_process_death_v2',
}
SAFE_TESTS = ('host::manual_enrollment::command::roster_publication_v2::sequential_construction_v3::qualification::durable_proposal_v1::delivery_admission_v2::durable_result_lifecycle_v2::partial_ready_paths_reject_escape_alias_and_unpreserved_container', 'host::manual_enrollment::command::roster_publication_v2::sequential_construction_v3::qualification::durable_proposal_v1::delivery_admission_v2::durable_result_lifecycle_v2::partial_death_marker_cannot_promote_old_profile_or_partial_line', 'host::manual_enrollment::command::roster_publication_v2::sequential_construction_v3::qualification::durable_proposal_v1::delivery_admission_v2::durable_result_lifecycle_v2::intake_death_marker_requires_exact_committed_ack_boundary', 'host::manual_enrollment::command::roster_publication_v2::sequential_construction_v3::qualification::durable_proposal_v1::delivery_admission_v2::durable_result_lifecycle_v2::started_death_marker_cannot_claim_result_or_unterminated_line', 'host::financial::private_financial_v2::qualification_fault_v2::tests::intake_ack_fault_latch_is_one_shot_exact_and_rejects_elapsed_arm', 'host::financial::durable_financial_commands_v2::tests::exact_two_owner_command_keys_are_disjoint_and_profile_specific', 'host::financial::durable_financial_commands_v2::tests::versioned_command_selector_rejects_unknown_fields', 'host::manual_enrollment::command::roster_publication_v2::sequential_construction_v3::qualification::durable_proposal_v1::delivery_admission_v2::durable_result_lifecycle_v2::durable_failure_v2_preserves_setup_and_tls_errors_without_private_text', 'host::manual_enrollment::command::roster_publication_v2::sequential_construction_v3::qualification::durable_proposal_v1::delivery_admission_v2::durable_result_lifecycle_v2::durable_failure_v2_projects_each_returned_stage_rejection_and_healthy_status', 'host::manual_enrollment::command::roster_publication_v2::sequential_construction_v3::qualification::durable_proposal_v1::delivery_admission_v2::durable_result_lifecycle_v2::durable_failure_v2_preserves_first_failure_through_all_cleanup_modes', 'host::manual_enrollment::command::roster_publication_v2::sequential_construction_v3::qualification::durable_proposal_v1::delivery_admission_v2::durable_result_lifecycle_v2::durable_failure_v2_covers_all_final_boundaries_and_diagnostic_states', 'host::manual_enrollment::command::roster_publication_v2::sequential_construction_v3::qualification::rolling_transcript_v1::delivery_first_failure_tests::delivery_first_failure_survives_more_than_64_later_diagnostics', 'host::manual_enrollment::command::roster_publication_v2::sequential_construction_v3::qualification::rolling_transcript_v1::delivery_first_failure_tests::delivery_first_failure_requires_complete_exact_finite_marker', 'host::manual_enrollment::command::roster_publication_v2::sequential_construction_v3::qualification::rolling_transcript_v1::delivery_first_failure_tests::delivery_first_failure_is_opt_in_and_isolated_per_child', 'host::manual_enrollment::command::roster_publication_v2::sequential_construction_v3::qualification::rolling_transcript_v1::delivery_first_failure_tests::delivery_first_failure_insufficient_capture_budget_is_sticky', 'host::manual_enrollment::command::roster_publication_v2::sequential_construction_v3::qualification::durable_proposal_v1::worker::admission_diagnostic_tests::durable_worker_state_layout_keeps_nominal_owners_indirect', 'host::manual_enrollment::command::roster_publication_v2::sequential_construction_v3::qualification::durable_proposal_v1::worker::admission_diagnostic_tests::durable_worker_execute_retains_inert_error_and_slot_order')
# Preserve the exact earlier SAFE17 prefix; append only owning finite-observer tests.
SAFE_TESTS += (
    'host::manual_enrollment::command::roster_publication_v2::sequential_construction_v3::qualification::rolling_transcript_v1::fatal_output_tests_v2::fatal_output_v2_actual_chunks_compaction_and_all_bit_orders',
    'host::manual_enrollment::command::roster_publication_v2::sequential_construction_v3::qualification::rolling_transcript_v1::fatal_output_tests_v2::fatal_output_v2_exact_grammar_truncation_and_private_fields',
    'host::manual_enrollment::command::roster_publication_v2::sequential_construction_v3::qualification::rolling_transcript_v1::fatal_output_tests_v2::fatal_output_v2_all_scan_refusals_preserve_original_behavior_and_sticky_loss',
    'host::manual_enrollment::command::roster_publication_v2::sequential_construction_v3::qualification::rolling_transcript_v1::fatal_output_tests_v2::fatal_output_v2_drain_loss_withholding_and_child_isolation',
    'host::manual_enrollment::command::roster_publication_v2::sequential_construction_v3::qualification::durable_proposal_v1::delivery_admission_v2::durable_result_lifecycle_v2::durable_failure_v2_fatal_observations_all_stages_keep_error_order_and_withhold',
)
NATIVE_SECONDS = 1800
ATTACH_SECONDS = 1830
ATTACH_SUITE_SECONDS = 3660
RUNTIME_SUITE_SECONDS = 4080  # Two attach bounds plus original bounded Docker control/cleanup.
RUNTIME_AND_CLEANUP_SECONDS = 4800  # Includes separate destructive cleanup reserve; no native work.
MAX_OUTPUT = 1024 * 1024
MAX_LINE = 8192
A_FIELDS = ('producer_killed_reaped_group_absent','signer_result_preintake_checkpoint_verified',
    'intake_ack_child_killed_reaped_group_absent','observed_original_writer_expiry',
    'first_result_outbox_unchanged','first_exposure_unchanged','counterpart_unsigned_at_death',
    'fresh_second_owner_completed','exact_union_extraction_verified',
    'local_read_return_intake_finish_verified','reader_reaped_group_absent',
    'six_scoped_protocol_refusals_verified','economic_proposal_verifier_succeeded',
    'cleanup_verified','native_runtime_executed','live_funds')
B_FIELDS = ('producer_killed_reaped_group_absent','actual_native_reopen_source_kernel_uncertain',
    'started_one_result_zero_outbox_zero_unchanged','exposure_outstanding_uncertain',
    'reader_reaped_group_absent','cleanup_verified','native_runtime_executed','live_funds',
    'not_full_v2_result_opener_or_return_success')
NATIVE_PROFILES = {'durable-resume':'durable-result-lifecycle-v2',
                   'durable-started':'durable-result-started-uncertainty-v2'}
NATIVE_MARKERS = {'durable-resume':b'CI_SYNTHETIC_DURABLE_RESULT_V2 ',
                  'durable-started':b'CI_SYNTHETIC_DURABLE_STARTED_V2 '}
FAILURES = ('selector','start','timeout','output_limit','native_assertion','schema','cleanup','context','internal')

# Existing finite native failure facts only; no transcript, new clock or authority.
NATIVE_FAILURE_MARKER = b'CI_SYNTHETIC_DURABLE_FAILURE_V2 '
FAILURE_COMMON_SITES = frozenset(('core_policy','child_wait_policy','cutoff','temporary_root','tls_prepare','temporary_cleanup','public_receipt'))
FAILURE_CASE_SITES = {
    'durable-resume': frozenset(('a0_producer','a0_ready_read','a0_ready_validate','a1_intake','writer_expiry_wait','a2_reader','a2_ready_read','a2_completion_read','a2_final_verify')),
    'durable-started': frozenset(('b_producer','b_ready_read','b_ready_validate','b_reader','b_ready_reread','b_completion_read','b_final_verify')),
}
FAILURE_VERIFICATION_SITES = frozenset(('a0_ready_validate','a2_final_verify','b_ready_validate','b_final_verify'))
FAILURE_REASONS = frozenset(('io_error','stage_call_error','stage_outcome_error','process_cleanup_unverified','expected_process_status','stage_deadline','verification','cleanup_unverified'))
FAILURE_IO_KINDS = frozenset(('not_found','permission_denied','connection','invalid_input','invalid_data','timed_out','interrupted','unexpected_eof','would_block','other'))
FAILURE_STAGE_EXPECTATIONS = {'a0_producer':(127,'sigkill'),'a1_intake':(23,'sigkill'),'a2_reader':(147,'success'),'b_producer':(118,'sigkill'),'b_reader':(0,'success')}
FAILURE_HARNESS_REASONS = frozenset(('Unclassified','Deadline','ChildObservation','ChildExit','PollIo','ReadIo','OutputLimit','IncompleteUtf8','InvalidUtf8','MultilineInput','WriteIo','FlushIo','MissingPathMarker','InvalidPath','InvalidChallenge','OutcomeRead','CleanupUnverified','FinancialPhaseDeadline','FinancialProgressInvalid'))
FAILURE_GROUP_SIGNALS = frozenset(('SentWhileLeaderOwned','AlreadyAbsentWhileLeaderOwned','Unverified'))
FAILURE_GROUP_ABSENCE = frozenset(('OriginalGroupAbsentObserved','Unverified'))
FAILURE_DIRECT_CHILD = frozenset(('Reaped','Unverified'))
FAILURE_CLEANUP = frozenset(('not_started','root_unavailable','closed_absent','close_unverified'))
# Exact inert copies of the current Rust financial enum domains; source-tested below.
FINANCIAL_STAGES = frozenset("NativeSourceOpen NativeHistoryRead NativeContinue NativeAdmit NativeAcquire NativeActivate NativeWalletPrepare NativeWalletObserve NativeSignPrepare NativeSign NativeReturnPrepare NativeHostPreparedWait NativeReturnApprove NativeReturnServe NativeReviewStage NativeResultRequest NativeAuthorityHistoryRead NativeFinancialHistoryRead NativeAuthorityAdmit NativeAuthorityAcquire NativeAuthorityActivate NativeAuthorityVerifyActive NativeWalletChain NativeWalletBirthday NativeWalletInitialize NativeWalletImport NativeWalletController NativeWalletVerify NativeWalletStatus NativeWalletMaterial NativeWalletSynchronize NativeWalletTicket NativeWalletReconcile LifecycleHarness WitnessHistoryService WitnessContinuationReview WitnessContinuationCommit WitnessSigningService WitnessCompletedPairService WitnessCompletedAccountService WitnessOriginalReopen WitnessOriginalPreserve WorkerCommand WorkerReply WorkerPhaseWait WorkerReview WorkerSourceOpen WorkerRequest WorkerReturn WorkerDrain InputValidation OriginalSource ReadConsent EffectConsent SourcePreparation RetentionContexts ContinuationBinding ResultPreview SignedRetentionApproval IntakeSetupApproval RetentionFreeze ResultReceive AuthenticatedIntake ResultFinishAcknowledgement UnionRetention TransactionCheckpoint CompletedVerification DispatchReview PairIntentRetention RetainedPairRead AdmissionFirst AdmissionSecond AdmissionReceiptRetention DispatchReverification BackendContext SavedTransactionHandoff DispatchOutcome FinancialHistory AuditSummary StaleRefusal Currentness ResultInstalledProviderVerification ResultHostPreparedWrite ResultReadyWait ResultFetchWrite ResultHeldRead ResultEvidenceValidation ResultPreviewMatch ResultCurrentProviderVerification ResultCurrentWrite ResultCurrentRead ResultCurrentMatch ResultFinishWrite ResultFinishRead ResultCurrentLock ResultCurrentPeer ResultReadyMatch ResultHeldMatch ResultFinishMatch".split())
FINANCIAL_COMPONENTS = frozenset("Store Journal StorageSecurity Signer Wallet Sync DurableConstruction WalletKeyUse Authority Host Engine SignerBridge Chain".split())
FINANCIAL_ERRORS = frozenset("StoreDatabase StoreEncoding StorePoisoned StoreIdempotencyConflict StoreRevisionConflict StoreNotFound StoreAlreadyExists StoreInvalidInput StoreUnsupportedSchema StoreRecoveryRequired StoreWriterEpochMismatch StoreLiveAuthorizationExists StoreInputReserved StoreResourceExhausted StoreBudgetExceeded StoreInvalidTransition StoreFile JournalStorage JournalDatabase JournalPermission JournalExpired JournalRecoveryRequired JournalUnsupportedSchema JournalOfflineHistoryUnsupported JournalNamedRecipientHistoryUnsupported JournalConstructionHistoryUnsupported JournalInvalidBinding JournalConflict JournalNotFound JournalLiveAuthorization JournalInputReserved JournalBudgetExceeded JournalLimit StorageUnsupportedPlatform StorageQuarantinedDatabase StorageRecoveredGeneration StorageGenerationArchive StorageUninitializedDatabase StorageUnsafePath StorageAlreadyExists StorageMissingDatabase StoragePlaintextRefused StorageUnqualifiedRuntime StorageAuthenticationFailed StorageDatabase StorageIo StorageSnapshotLimit StorageSourceChanged Unavailable PeerLifetimeUnavailable Io InvalidData Crypto BackupRequired AlreadyOpen ReviewMismatch ConsentJournal Store Limit CompleteOriginRecoveryUnavailable AuthorityInvalidBinding AuthorityPermission AuthorityStaleHead AuthorityConflict AuthorityInactive AuthorityRecoveryRequired AuthorityExpired AuthorityPolicyDenied AuthorityBudgetExceeded AuthorityInputReserved AuthorityObligationReserved AuthorityLimit AuthorityStorage AuthorityCorruptHistory AuthorityPermanentStopUnavailable AuthorityOfflineHistoryUnsupported AuthorityConstructionHistoryUnsupported AuthorityUnsupportedVersion AuthorityAuthentication AuthorityUncertain AuthorityResolutionUnavailable AuthoritySessionRequired AuthoritySessionPending WalletStorage WalletAccountScope WalletAccountMismatch WalletIncompleteSync WalletUnsupportedProfile WalletChainMismatch WalletInsufficientFunds WalletInvalidRequest WalletMissingWitness WalletInvalidNote WalletScan WalletTransport SyncAccessDenied SyncInvalidRequest SyncInterrupted SyncReconciliationRequired SyncInvalidResponse SyncResourceLimit SyncNoCurrentObservation ChainInvalidConfiguration ChainWrongNetwork ChainUnsupportedProxyConfiguration ChainWrongBranch ChainStaleChain ChainContradictoryChain ChainTimeout ChainTransportUnavailable ChainObservationInterrupted ChainMissingAncestryEvidence ChainNotObserved ChainResourceLimit ChainMalformedEvidence ChainUnsupportedCapability ChainBackendFailure ChainClockUnavailable ChainIdempotencyConflict ChainJournalFailure ChainSubmissionNotAuthorized ChainSubmissionExpiryMargin ChainObligationConflict ChainSubmissionOutcomeUnrecorded ChainSubmissionRetentionUncertain DurableInvalid DurableBinding DurableStale DurableStorage KeyUsePermission KeyUsePolicy KeyUseSelectionExpired KeyUseStorage KeyUseRecoveryRequired KeyUseStateChanged KeyUseExpiry StaleHead Inactive PolicyDenied BudgetExceeded InputReserved ObligationReserved CorruptHistory SessionRequired SessionPending Permission Binding Conflict Missing RecoveryRequired Verification Storage ResourceLimit Expired Uncertain Unsupported Authentication Terminal Invalid Locked Ipc Journal Authority Wallet SignerOriginUnavailable DurableProposalConflict DurableProposalRecoveryRequired SignaturesIncomplete RetentionDenied RetentionConflict OriginalIntentMissing RetentionRecoveryRequired SubmissionUnresolved FinancialOutcomeReconciliation RevisionConflict Timeout Interrupted TransportUnavailable WrongNetwork WrongBranch StaleChain ContradictoryChain BackendFailure ClockUnavailable Other FrameUnclassified FrameDeadline FrameEof FrameCredentialsMissing FrameCredentialsMismatch FrameAncillaryRejected FrameTruncated FramePeerNotLive FrameCurrentCheck FrameIo FrameLimit FrameInvalid FrameInvalidBudget".split())
FINANCIAL_COMMIT_STATES = frozenset("NotEstablished IntakeCommitted OutcomeUncertain".split())
PRIVATE_FIXED_PRIMARY_FIELDS = frozenset(('cause', 'engine_code', 'family', 'operation', 'site'))
PRIVATE_FIXED_OPERATIONS = frozenset(('Checkpoint', 'Freeze', 'OpenOriginal', 'Proof', 'ReadFixed'))
PRIVATE_FIXED_SITES = frozenset(('Candidate', 'ConstructorReload', 'ContinuationBinding', 'CurrentTerms', 'Enqueue', 'EnvelopeCompare', 'ExactScope', 'FinalGate', 'FinalProofOrigin', 'FixedCommit', 'FixedMappings', 'FixedPrepare', 'FixedReplayRead', 'FixedVerify', 'GateHeldPost', 'GateHeldPre', 'GateMaterial', 'GateProofConsent', 'GateWorkspace', 'HeldPostcheck', 'HeldPrecheck', 'HostCheckpointAction', 'HostCheckpointContinuation', 'HostCheckpointEntry', 'HostCheckpointPostcheck', 'HostCheckpointSlots', 'HostFreezeAction', 'HostFreezeEntry', 'HostFreezeReturn', 'HostMaterialApproval', 'HostMaterialNativeCheck', 'HostMaterialScope', 'HostProofAccess', 'HostProofApproval', 'HostProofFinalCheck', 'HostProofForegroundMessage', 'HostProofJoin', 'HostProofNativeCheck', 'HostProofPrecheck', 'HostProofReceive', 'HostProofScope', 'HostReadAction', 'HostReadOpen', 'HostReadReturn', 'HostReadSession', 'HostWorkspaceCurrent', 'HostWorkspaceNativeCheck', 'HostWorkspaceSessionCheck', 'HostWorkspaceSourceCheck', 'InputRequestDigest', 'JournalAfterRead', 'LinkCommit', 'LinkPrepare', 'LinkUpsert', 'LoadVerified', 'LogicalCompare', 'Marker', 'MaterialRoster', 'MetadataOpen', 'MetadataOrigin', 'MetadataPreflight', 'OperationHistory', 'OriginalLineage', 'OriginalLookup', 'OriginalRequest', 'OutcomeCommit', 'OutcomePrepare', 'OutputCommitments', 'OutputLineage', 'PostConsent', 'PostSource', 'ProofEventHistory', 'ProofOrigin', 'ProofResultLineage', 'ProofRun', 'ProofVerifiedState', 'ProposalValidation', 'ProtocolConstruct', 'ProtocolInspect', 'ReaderCommitments', 'ReaderComparisonVerify', 'ReaderCompletionWrite', 'ReaderControlRead', 'ReaderEnroll', 'ReaderFinalRegistry', 'ReaderFinalReturn', 'ReaderFinancialCompare', 'ReaderFinancialOpen', 'ReaderFinancialOriginal', 'ReaderFinancialSnapshot', 'ReaderHostReturn', 'ReaderHostRuntime', 'ReaderMetadataInitializedSchema', 'ReaderMetadataOrigin', 'ReaderMetadataSnapshot', 'ReaderOriginalFinancialHandles', 'ReaderOriginalFinancialLoad', 'ReaderOriginalFinancialProofSchema', 'ReaderOriginalProofCurrent', 'ReaderOriginalProofSource', 'ReaderProfileDirectory', 'ReaderProofSnapshotOpen', 'ReaderProofSnapshotOrigin', 'ReaderProofSnapshotUnchanged', 'ReaderReadSession', 'ReaderSavedPrincipal', 'ReaderSourceAssociation', 'ReaderSourceCompare', 'ReaderSourceFinalCheck', 'ReaderSourceOpen', 'ReaderSourceSeedBinding', 'ReaderSourceSeedCompare', 'ReaderSourceSeedPlan', 'ReaderSourceSelection', 'ReaderSourceStore', 'ReaderVaultRead', 'ReaderVaultV3Open', 'ReaderWorkspaceDirectory', 'ReceiptCommit', 'ReceiptPrepare', 'ReloadAfterEnqueue', 'ReloadAfterRead', 'ReplayLookup', 'RetainConsent', 'RetainedDiscovery', 'RetainedKey', 'Revision', 'SavedDecode', 'SeedAudit', 'SeedBinding', 'SeedFinal', 'SeedOperation', 'SeedPlan', 'SeedRecord', 'SeedReplay', 'SlotBindings', 'SnapshotInventory', 'SnapshotOpen', 'SnapshotOrigin', 'SnapshotSchema', 'SnapshotSourceUnchanged', 'SourcePermission', 'StatusLookup', 'WalletRosterAcquire', 'WalletRosterRelease', 'WorkspaceLoad'))
PRIVATE_FIXED_ENGINE_CODES = frozenset(('ACCESS_DENIED', 'CANDIDATE_VERIFICATION_FAILED', 'CONSERVATION_FAILURE', 'DEBIT_CAP_EXCEEDED', 'DISCLOSURE_DENIED', 'DUPLICATE_IDENTIFIER', 'DURABLE_CONSTRUCTION_UNAVAILABLE', 'DURABLE_PROFILE_UNAVAILABLE', 'DURABLE_PROPOSAL_CONFLICT', 'DURABLE_PROPOSAL_NOT_FOUND', 'DURABLE_PROPOSAL_RECOVERY_REQUIRED', 'FEE_CAP_EXCEEDED', 'IDEMPOTENCY_CONFLICT', 'INTERNAL_ERROR', 'INVALID_AMOUNT', 'INVALID_REQUEST', 'INVALID_TERMS', 'INVALID_TRANSITION', 'LIVE_AUTHORIZATION_EXISTS', 'MANUAL_CONSTRUCTION_DENIED', 'MISSING_EVIDENCE', 'NOT_FOUND', 'NotApplicable', 'OUTSTANDING_EXPOSURE', 'PERMISSION_DENIED', 'PRIVACY_INCOMPATIBLE', 'RECOVERY_REQUIRED', 'RESOURCE_EXHAUSTED', 'RESOURCE_LIMIT', 'RETAINED_INPUT_OBSERVATION_UNAVAILABLE', 'REVISION_CONFLICT', 'STALE_CHAIN', 'STORAGE_PROTECTION_REQUIRED', 'STORAGE_UNAVAILABLE', 'UNKNOWN_PARTICIPANT', 'UNSUPPORTED_CAPABILITY', 'UNSUPPORTED_VERSION', 'UNVERIFIABLE_MATCH', 'USER_REJECTED', 'Unclassified'))
PRIVATE_FIXED_FAMILIES = {'Engine': ('ACCESS_DENIED', 'CANDIDATE_VERIFICATION_FAILED', 'CONSERVATION_FAILURE', 'DEBIT_CAP_EXCEEDED', 'DISCLOSURE_DENIED', 'DUPLICATE_IDENTIFIER', 'DURABLE_CONSTRUCTION_UNAVAILABLE', 'DURABLE_PROFILE_UNAVAILABLE', 'DURABLE_PROPOSAL_CONFLICT', 'DURABLE_PROPOSAL_NOT_FOUND', 'DURABLE_PROPOSAL_RECOVERY_REQUIRED', 'FEE_CAP_EXCEEDED', 'IDEMPOTENCY_CONFLICT', 'INTERNAL_ERROR', 'INVALID_AMOUNT', 'INVALID_REQUEST', 'INVALID_TERMS', 'INVALID_TRANSITION', 'LIVE_AUTHORIZATION_EXISTS', 'MANUAL_CONSTRUCTION_DENIED', 'MISSING_EVIDENCE', 'NOT_FOUND', 'OUTSTANDING_EXPOSURE', 'PERMISSION_DENIED', 'PRIVACY_INCOMPATIBLE', 'RECOVERY_REQUIRED', 'RESOURCE_EXHAUSTED', 'RESOURCE_LIMIT', 'RETAINED_INPUT_OBSERVATION_UNAVAILABLE', 'REVISION_CONFLICT', 'STALE_CHAIN', 'STORAGE_PROTECTION_REQUIRED', 'STORAGE_UNAVAILABLE', 'UNKNOWN_PARTICIPANT', 'UNSUPPORTED_CAPABILITY', 'UNSUPPORTED_VERSION', 'UNVERIFIABLE_MATCH', 'USER_REJECTED', 'Unclassified'), 'DurableConstruction': ('Binding', 'Invalid', 'Stale', 'Storage', 'Unclassified'), 'Sync': ('AccessDenied', 'Interrupted', 'InvalidRequest', 'InvalidResponse', 'NoCurrentObservation', 'ReconciliationRequired', 'ResourceLimit', 'Unclassified'), 'Wallet': ('AccountMismatch', 'AccountScope', 'ChainMismatch', 'IncompleteSync', 'InsufficientFunds', 'InvalidNote', 'InvalidRequest', 'MissingWitness', 'Scan', 'Storage', 'Transport', 'Unclassified', 'UnsupportedProfile'), 'Chain': ('BackendFailure', 'ClockUnavailable', 'ContradictoryChain', 'IdempotencyConflict', 'InvalidConfiguration', 'JournalFailure', 'MalformedEvidence', 'MissingAncestryEvidence', 'NotObserved', 'ObligationConflict', 'ObservationInterrupted', 'ResourceLimit', 'StaleChain', 'SubmissionExpiryMargin', 'SubmissionNotAuthorized', 'SubmissionOutcomeUnrecorded', 'SubmissionRetentionUncertain', 'Timeout', 'TransportUnavailable', 'Unclassified', 'UnsupportedCapability', 'UnsupportedProxyConfiguration', 'WrongBranch', 'WrongNetwork'), 'Protocol': ('ActionMapping', 'BuilderInput', 'BuilderOutput', 'Context', 'Contribution', 'Disclosure', 'Fee', 'Finalize', 'FixedAccounting', 'FixedBudget', 'FixedCanonicalAccount', 'FixedDistinctAccounts', 'FixedOwners', 'FixedPaddingSignature', 'FixedPolicy', 'FixedProofOnlyTransition', 'FixedRealInput', 'FixedRecipient', 'FixedUnsignedPredecessor', 'FixedUnsignedRealInput', 'Input', 'Manifest', 'Output', 'Pczt', 'Unclassified'), 'Store': ('AlreadyExists', 'BudgetExceeded', 'Database', 'Encoding', 'File', 'IdempotencyConflict', 'InputReserved', 'InvalidInput', 'InvalidTransition', 'LiveAuthorizationExists', 'NotFound', 'Poisoned', 'RecoveryRequired', 'ResourceExhausted', 'RevisionConflict', 'StorageSecurity', 'Unclassified', 'UnsupportedSchema', 'WriterEpochMismatch'), 'StorageSecurity': ('AlreadyExists', 'AuthenticationFailed', 'Database', 'GenerationArchive', 'Io', 'MissingDatabase', 'PlaintextRefused', 'QuarantinedDatabase', 'RecoveredGeneration', 'SnapshotLimit', 'SourceChanged', 'Unclassified', 'UninitializedDatabase', 'UnqualifiedRuntime', 'UnsafePath', 'UnsupportedPlatform'), 'Job': ('ConsentDenied', 'IdempotencyConflict', 'InvalidRequest', 'NotFound', 'RecoveryRequired', 'ResourceExhausted', 'StateConflict', 'Storage', 'Unclassified', 'UnsupportedSchema', 'VerificationFailed'), 'Gate': ('ExactScopeMismatch', 'MaterialConsentFalse', 'ProofConsentFalse', 'Unclassified', 'WorkspaceConsentFalse'), 'Host': ('Authentication', 'CompleteOriginRecoveryUnavailable', 'GenerationArchiveIncomplete', 'HistoricalExportIncomplete', 'Invalid', 'Locked', 'Permission', 'Platform', 'Quarantined', 'Receipt', 'RecoveryBackupUnsupported', 'RecoveryFinancialUnsupported', 'RecoverySemantic', 'Storage', 'Terminal', 'Unclassified', 'Unsupported')}
FAILURE_DELIVERY_BOUNDARIES = frozenset(('DeliveryAdmissionAfterReadChannel', 'DeliveryAdmissionAfterReadSource', 'DeliveryAdmissionAfterWriteChannel', 'DeliveryAdmissionAfterWriteSource', 'DeliveryAdmissionBeforeSendChannel', 'DeliveryAdmissionBeforeSendSource', 'DeliveryAdmissionBeforeWriteChannel', 'DeliveryAdmissionCommittedHead', 'DeliveryAdmissionFlushIo', 'DeliveryAdmissionFlushPostcheck', 'DeliveryAdmissionFlushPrecheck', 'DeliveryAdmissionReadFrame', 'DeliveryAdmissionReadIo', 'DeliveryAdmissionReadPostcheck', 'DeliveryAdmissionReadPrecheck', 'DeliveryAdmissionResponseRejected', 'DeliveryAdmissionResponseVariant', 'DeliveryAdmissionRetainedBinding', 'DeliveryAdmissionSnapshot', 'DeliveryAdmissionWriteFrame', 'DeliveryAdmissionWriteIo', 'DeliveryAdmissionWritePostcheck', 'DeliveryAdmissionWritePrecheck', 'DeliveryArtifactImport', 'DeliveryArtifactImportStart', 'DeliveryCredentialRegistration', 'DeliveryDurableMarker', 'DeliveryExportApproval', 'DeliveryExportCheckpointScope', 'DeliveryExportCommand', 'DeliveryExportCommit', 'DeliveryExportDelta', 'DeliveryExportEntry', 'DeliveryExportHistory', 'DeliveryExportIntake', 'DeliveryExportMarker', 'DeliveryExportMaterialCeilings', 'DeliveryExportMetadataOrigin', 'DeliveryExportOutputActions', 'DeliveryExportPayload', 'DeliveryExportPermission', 'DeliveryExportPostcheck', 'DeliveryExportPreview', 'DeliveryExportProofCurrent', 'DeliveryExportProofOrigin', 'DeliveryExportProofPermission', 'DeliveryExportRecipientBinding', 'DeliveryExportReplayLookup', 'DeliveryExportReplayScope', 'DeliveryExportRoster', 'DeliveryExportScopePredicate', 'DeliveryExportSourceAfter', 'DeliveryExportSourceBefore', 'DeliveryExportSources', 'DeliveryExportVerifiedProof', 'DeliveryHistoricalRead', 'DeliveryIdentityCompare', 'DeliveryMaterialActionPredicate', 'DeliveryMaterialScopePredicate', 'DeliveryNativeAdmission', 'DeliveryNativeCheck', 'DeliveryOriginalReopen', 'DeliveryProducerKill', 'DeliveryProducerReap', 'DeliveryProofRolePredicate', 'DeliveryReaderReap', 'DeliveryReceiveAccount', 'DeliveryReceiveAccountBinding', 'DeliveryReceiveChunkDecode', 'DeliveryReceiveCommandBinding', 'DeliveryReceiveCommandParse', 'DeliveryReceiveContributionBinding', 'DeliveryReceiveCurrentHistory', 'DeliveryReceiveCurrentWrite', 'DeliveryReceiveDeadline', 'DeliveryReceiveEconomics', 'DeliveryReceiveFinalBinding', 'DeliveryReceiveFinalDeadline', 'DeliveryReceiveFinalMaterialClock', 'DeliveryReceiveFinalMaterialScope', 'DeliveryReceiveFinalPeer', 'DeliveryReceiveFinalSource', 'DeliveryReceiveFrame', 'DeliveryReceiveImportedWrite', 'DeliveryReceiveLease', 'DeliveryReceiveMaterialClock', 'DeliveryReceiveMaterialOwner', 'DeliveryReceiveMaterialScope', 'DeliveryReceiveNativeDeadline', 'DeliveryReceiveNativeOrigin', 'DeliveryReceiveOriginalBinding', 'DeliveryReceiveOriginalHistory', 'DeliveryReceiveOriginalSource', 'DeliveryReceivePayloadBinding', 'DeliveryReceivePayloadCanonical', 'DeliveryReceivePayloadLimit', 'DeliveryReceivePayloadParse', 'DeliveryReceivePeer', 'DeliveryReceiveProposal', 'DeliveryReceiveProvedDecode', 'DeliveryReceiveReadyWrite', 'DeliveryReceiveReceipts', 'DeliveryReceiveReceivingWrite', 'DeliveryReceiveRecipientBinding', 'DeliveryReceiveRedisclosureBinding', 'DeliveryReceiveRequest', 'DeliveryReceiveRequestDigest', 'DeliveryReceiveReviewerScope', 'DeliveryReceiveSource', 'DeliveryReceiveSourceUnderLease', 'DeliveryReceiveTerminal', 'DeliveryReceiveUnsignedDecode', 'DeliveryReceiveViewingKey', 'DeliveryRecipientDeadline', 'DeliveryRecipientFrame', 'DeliveryRecipientMutex', 'DeliveryRecipientObserverClone', 'DeliveryRecipientOrigin', 'DeliveryRecipientPrepare', 'DeliveryRecipientResponse', 'DeliveryRecipientResponseDecode', 'DeliveryRecipientResponseDigest', 'DeliveryRecipientWriteDeadline', 'DeliveryRecipientWriteEmpty', 'DeliveryRecipientWriteIo', 'DeliveryRecipientWriteLimit', 'DeliveryRecipientWriteSerialize', 'DeliveryRecipientWriteTimeout', 'DeliveryRedisclosure', 'DeliveryRedisclosureApprove', 'DeliveryRedisclosurePrepare', 'DeliveryRedisclosureServe', 'DeliveryRootCleanup', 'DeliverySourceCheck', 'DeliverySourceExport', 'DeliverySourceInspection', 'DeliverySourceOpen', 'DeliverySourcePlan', 'DeliverySourceScopePredicate', 'DeliveryUnsupportedAudit', 'PrivateSourceSelect', 'PrivateWorkspaceAnchor', 'PrivateWorkspaceBootstrap', 'PrivateWorkspaceCandidate', 'PrivateWorkspaceCapture', 'PrivateWorkspaceCheckpoint', 'PrivateWorkspaceDurableMarker', 'PrivateWorkspaceFreeze', 'PrivateWorkspaceIdentityCompare', 'PrivateWorkspaceInitialize', 'PrivateWorkspaceIntake', 'PrivateWorkspaceObserve', 'PrivateWorkspaceProducerKill', 'PrivateWorkspaceProducerReap', 'PrivateWorkspaceProof', 'PrivateWorkspacePublish', 'PrivateWorkspaceReadFixed', 'PrivateWorkspaceReaderOpen', 'PrivateWorkspaceReaderReap', 'PrivateWorkspaceReserve', 'PrivateWorkspaceRootCleanup', 'PrivateWorkspaceScanCleanup'))
FAILURE_DELIVERY_OUTCOMES = frozenset(('AuthorityAuthentication', 'AuthorityBudgetExceeded', 'AuthorityConflict', 'AuthorityConstructionHistoryUnsupported', 'AuthorityCorruptHistory', 'AuthorityExpired', 'AuthorityInactive', 'AuthorityInputEmpty', 'AuthorityInputOverBound', 'AuthorityInputReserved', 'AuthorityInputWithinBound', 'AuthorityInvalidBinding', 'AuthorityIoBrokenPipe', 'AuthorityIoConnectionAborted', 'AuthorityIoConnectionRefused', 'AuthorityIoConnectionReset', 'AuthorityIoInterrupted', 'AuthorityIoInvalidData', 'AuthorityIoInvalidInput', 'AuthorityIoNotConnected', 'AuthorityIoOther', 'AuthorityIoPermissionDenied', 'AuthorityIoTimedOut', 'AuthorityIoUnexpectedEof', 'AuthorityIoWouldBlock', 'AuthorityIoWriteZero', 'AuthorityLimit', 'AuthorityObligationReserved', 'AuthorityOfflineHistoryUnsupported', 'AuthorityPermanentStopUnavailable', 'AuthorityPermission', 'AuthorityPolicyDenied', 'AuthorityRecoveryRequired', 'AuthorityResolutionUnavailable', 'AuthoritySessionPending', 'AuthoritySessionRequired', 'AuthorityStaleHead', 'AuthorityStorage', 'AuthorityUncertain', 'AuthorityUnsupportedVersion', 'BridgeAuthority', 'BridgeBinding', 'BridgeCompleteOriginRecoveryUnavailable', 'BridgeConflict', 'BridgeIpc', 'BridgeJournal', 'BridgeLimit', 'BridgeMissing', 'BridgePermission', 'BridgeRecoveryRequired', 'BridgeSignerOriginUnavailable', 'BridgeUncertain', 'BridgeVerification', 'BridgeWallet', 'ChainBackendFailure', 'ChainClockUnavailable', 'ChainContradictoryChain', 'ChainIdempotencyConflict', 'ChainInvalidConfiguration', 'ChainJournalFailure', 'ChainMalformedEvidence', 'ChainMissingAncestryEvidence', 'ChainNotObserved', 'ChainObligationConflict', 'ChainObservationInterrupted', 'ChainResourceLimit', 'ChainStaleChain', 'ChainSubmissionExpiryMargin', 'ChainSubmissionNotAuthorized', 'ChainSubmissionOutcomeUnrecorded', 'ChainSubmissionRetentionUncertain', 'ChainTimeout', 'ChainTransportUnavailable', 'ChainUnsupportedCapability', 'ChainUnsupportedProxyConfiguration', 'ChainWrongBranch', 'ChainWrongNetwork', 'ConstructionBinding', 'ConstructionInvalid', 'ConstructionStale', 'ConstructionStorage', 'ConstructionSync', 'EngineAccessDenied', 'EngineCandidateVerificationFailed', 'EngineDebitCapExceeded', 'EngineDisclosureDenied', 'EngineDisclosureUnknown', 'EngineDurableConstructionUnavailable', 'EngineDurableProfileUnavailable', 'EngineDurableProposalConflict', 'EngineDurableProposalRecoveryRequired', 'EngineIdempotencyConflict', 'EngineInternalError', 'EngineInvalidRequest', 'EngineInvalidTerms', 'EngineInvalidTransition', 'EngineLiveAuthorizationExists', 'EngineManualConstructionDenied', 'EngineMissingEvidence', 'EngineNotFound', 'EnginePermissionDenied', 'EngineRecoveryRequired', 'EngineResourceExhausted', 'EngineRetainedObservationUnavailable', 'EngineRevisionConflict', 'EngineStorageProtectionRequired', 'EngineStorageUnavailable', 'EngineUnclassified', 'EngineUnsupportedCapability', 'ExactBinding', 'ExactBudget', 'ExactLineage', 'ExactPermission', 'ExactProfileChanged', 'ExactRecoveryRequired', 'ExactRoster', 'ExactStateChanged', 'ExactStorage', 'HostAuthentication', 'HostCompleteOriginRecoveryUnavailable', 'HostGenerationArchiveIncomplete', 'HostHistoricalExportIncomplete', 'HostInvalid', 'HostLocked', 'HostPermission', 'HostPlatform', 'HostQuarantined', 'HostReceipt', 'HostRecoveryBackupUnsupported', 'HostRecoveryFinancialUnsupported', 'HostRecoverySemantic', 'HostStorage', 'HostTerminal', 'HostUnsupported', 'ImportBinding', 'ImportFreshOwnerRequired', 'ImportIncomplete', 'ImportStorage', 'JobConsentDenied', 'JobIdempotencyConflict', 'JobInvalidRequest', 'JobNotFound', 'JobRecoveryRequired', 'JobResourceExhausted', 'JobStateConflict', 'JobStorage', 'JobUnsupportedSchema', 'JobVerificationFailed', 'JournalExpired', 'JournalOther', 'JournalPermission', 'OriginAuthentication', 'OriginBinding', 'OriginConflict', 'OriginCrypto', 'OriginFrameAncillaryRejected', 'OriginFrameCredentialsMismatch', 'OriginFrameCredentialsMissing', 'OriginFrameCurrentCheck', 'OriginFrameDeadline', 'OriginFrameEof', 'OriginFrameInvalidBudget', 'OriginFrameInvalidFrame', 'OriginFrameIo', 'OriginFrameLimit', 'OriginFramePeerNotLive', 'OriginFrameTruncated', 'OriginFrameUnclassified', 'OriginInvalidData', 'OriginIoBrokenPipe', 'OriginIoConnectionAborted', 'OriginIoConnectionReset', 'OriginIoInterrupted', 'OriginIoNotConnected', 'OriginIoOther', 'OriginIoPermissionDenied', 'OriginIoTimedOut', 'OriginIoUnexpectedEof', 'OriginIoWouldBlock', 'OriginIpc', 'OriginLimit', 'OriginLocked', 'OriginPeerLifetimeUnavailable', 'OriginPermanentStopUnavailable', 'OriginPermission', 'OriginRetirementEvidenceUnavailable', 'OriginSignerOriginUnavailable', 'PredicateDenied', 'ProtocolActionMapping', 'ProtocolBuilderInput', 'ProtocolBuilderOutput', 'ProtocolContext', 'ProtocolContribution', 'ProtocolDisclosure', 'ProtocolFee', 'ProtocolFinalize', 'ProtocolInput', 'ProtocolManifest', 'ProtocolOutput', 'ProtocolPczt', 'ProtocolUnclassified', 'RecoveryAccessDenied', 'RecoveryAdditionalEvidenceRequired', 'RecoveryIncompleteScan', 'RecoveryKnownFundsRemain', 'RecoveryUnsupportedAccountComponents', 'SignerAlreadyOpen', 'SignerAuthentication', 'SignerBackupRequired', 'SignerConsentJournal', 'SignerCrypto', 'SignerInvalidData', 'SignerIo', 'SignerLocked', 'SignerPeerLifetimeUnavailable', 'SignerRecoveryRequired', 'SignerReviewMismatch', 'SignerStore', 'SignerUnavailable', 'SignerUncertain', 'SignerVerification', 'StoreAlreadyExists', 'StoreBudgetExceeded', 'StoreDatabase', 'StoreEncoding', 'StoreFile', 'StoreIdempotencyConflict', 'StoreInputReserved', 'StoreInvalidInput', 'StoreInvalidTransition', 'StoreLiveAuthorizationExists', 'StoreNotFound', 'StorePoisoned', 'StoreRecoveryRequired', 'StoreResourceExhausted', 'StoreRevisionConflict', 'StoreStorageSecurity', 'StoreUnsupportedSchema', 'StoreWriterEpochMismatch', 'SyncAccessDenied', 'SyncInterrupted', 'SyncInvalidRequest', 'SyncInvalidResponse', 'SyncNoCurrentObservation', 'SyncReconciliationRequired', 'SyncResourceLimit', 'WalletAccountMismatch', 'WalletAccountScope', 'WalletChainMismatch', 'WalletIncompleteSync', 'WalletInsufficientFunds', 'WalletInvalidNote', 'WalletInvalidRequest', 'WalletMissingWitness', 'WalletScan', 'WalletStorage', 'WalletTransport', 'WalletUnsupportedProfile', 'WorkerFailure'))

class Rejected(Exception):
    def __init__(self, code):
        self.code = code if code in FAILURES else 'internal'
        super().__init__(self.code)

def need(ok, code='schema'):
    if not ok: raise Rejected(code)

def pairs(items):
    value = {}
    for key, item in items:
        need(key not in value); value[key] = item
    return value

def loads(raw):
    need(type(raw) is bytes and 0 < len(raw) <= MAX_LINE)
    try:
        return json.loads(raw, object_pairs_hook=pairs,
            parse_constant=lambda _: (_ for _ in ()).throw(Rejected('schema')))
    except (ValueError, UnicodeError, RecursionError): raise Rejected('schema') from None

def recipe():
    return dict(build_recipe_version=5, qualification_profile=PROFILE,
        execution='native-owner-durable-correctness-selective-optimization',
        toolchain='1.99.0',rustc='rustc 1.99.0 (b940084d7 2026-09-28)',target='x86_64-unknown-linux-gnu',
        jobs=3,incremental=False,profile='release',default_features=False,
        host_test_features=FEATURE_TEXT,cargo_config_overrides=list(OVERRIDES),
        host_opt_level=3,signer_opt_level=1,engine_opt_level=0,
        debug_assertions=False,overflow_checks=False,other_dependencies_release_optimized=True,
        rustflags='',sqlcipher='4.19.0',openssl='3.5.9',static_crypto=True,platform='linux-amd64',locked=True,
        artifact_features={ROLE:list(FEATURES)},test_selectors=dict(CASES),safe_test_selectors=list(SAFE_TESTS),
        cfg_delivery=dict(mechanism='cargo-build-script-v1',mode_environment='WHOLEPACT_FINANCIAL_BUILD_MODE',
            build_scripts=['crates/wholepact-native-host/build.rs','crates/wholepact-signer/build.rs'],
            artifact_script_crates={ROLE:['wholepact-native-host','wholepact-signer']},
            artifact_modes={ROLE:'production'},effective_cfgs={ROLE:[]},global_financial_cfgs_permitted=False))

def validate_package_profiles(raw, repo):
    expected = {str(pathlib.Path(repo)/'crates'/name/'Cargo.toml'):name
                for name in ('wholepact-signer','wholepact-engine')}
    found = set()
    for line in raw.splitlines():
        need(len(line) <= 2*1024*1024)
        try: row = json.loads(line)
        except (ValueError,UnicodeError): continue
        if type(row) is not dict or row.get('reason') != 'compiler-artifact': continue
        name = expected.get(row.get('manifest_path'))
        if name is None: continue
        target, profile = row.get('target'), row.get('profile')
        if type(target) is not dict or target.get('kind') != ['lib']: continue
        need(target.get('name') == name.replace('-','_') and type(profile) is dict
             and profile.get('opt_level') == ('1' if name=='wholepact-signer' else '0')
             and profile.get('debug_assertions') is False
             and profile.get('test') is False)
        need(profile.get('overflow_checks') is False)
        need(name not in found); found.add(name)
    need(found == {'wholepact-signer','wholepact-engine'})

def safe_test_passed(selector, raw):
    """Producer-only exact safe test; never accepts the ignored lifecycle cases."""
    need(selector in SAFE_TESTS and type(raw) is bytes and len(raw)<=MAX_OUTPUT,'selector')
    named=summary=0
    for line in raw.splitlines():
        need(len(line)<=MAX_LINE,'output_limit')
        if line.startswith(b'test ') and not line.startswith(b'test result:'):
            need(line == b'test '+selector.encode()+b' ... ok','selector');named+=1
        if line.startswith(b'test result:'):
            need(re.fullmatch(rb'test result: ok\. 1 passed; 0 failed; 0 ignored; 0 measured; [0-9]{1,6} filtered out; finished in [0-9]{1,4}\.[0-9]{2}s',line) is not None,'native_assertion')
            summary+=1
    need(named==summary==1,'selector')

def native_receipt(case, raw):
    need(case in CASES, 'selector')
    value = loads(raw)
    fields = A_FIELDS if case == 'durable-resume' else B_FIELDS
    need(type(value) is dict and set(value) == {'profile',*fields}
         and value['profile'] == NATIVE_PROFILES[case])
    need(all(type(value[name]) is bool for name in fields))
    return value

def native_passed(case, value):
    fields = A_FIELDS if case == 'durable-resume' else B_FIELDS
    return all(value[name] is (name != 'live_funds') for name in fields)

def native_failure(case, raw):
    """Strict source-bound observation, never proof of the initiating root cause."""
    need(case in CASES,'selector')
    value=loads(raw)
    need(type(value) is dict and set(value)=={'schema','case','callsite','reason','io_kind','stage','cleanup'})
    need(type(value['schema']) is int and value['schema']==1 and value['case']==case)
    site=value['callsite']
    need(type(site) is str and site in FAILURE_COMMON_SITES|FAILURE_CASE_SITES[case])
    need(type(value['reason']) is str and value['reason'] in FAILURE_REASONS
         and type(value['io_kind']) is str and value['io_kind'] in FAILURE_IO_KINDS
         and type(value['cleanup']) is str and value['cleanup'] in FAILURE_CLEANUP)
    stage=value['stage']
    stage_reasons={'stage_outcome_error','process_cleanup_unverified','expected_process_status','stage_deadline'}
    if site in FAILURE_STAGE_EXPECTATIONS:
        need(value['reason'] in stage_reasons|{'stage_call_error'})
        need((stage is None)==(value['reason']=='stage_call_error'))
    else:
        expected_reason=('verification' if site in FAILURE_VERIFICATION_SITES else
                         'cleanup_unverified' if site=='temporary_cleanup' else 'io_error')
        need(value['reason']==expected_reason and stage is None)
    if stage is None:return value
    if value['reason']=='stage_deadline':need(site in ('a2_reader','b_reader'))
    need(site in FAILURE_STAGE_EXPECTATIONS and type(stage) is dict and set(stage)=={
        'failure_reason','next','expected','expected_process','group_signal','group_absence','direct_child',
        'status_kind','status_value','diagnostic_state','private_fixed_primary','delivery_first_failure','financial_first_failure','fatal_observation'})
    expected,process=FAILURE_STAGE_EXPECTATIONS[site]
    need(type(stage['failure_reason']) is str and stage['failure_reason'] in FAILURE_HARNESS_REASONS
         and type(stage['next']) is int and type(stage['expected']) is int
         and stage['expected']==expected and 0<=stage['next']<=expected and stage['expected_process']==process)
    for key,labels in (('group_signal',FAILURE_GROUP_SIGNALS),('group_absence',FAILURE_GROUP_ABSENCE),('direct_child',FAILURE_DIRECT_CHILD)):
        need(type(stage[key]) is str and stage[key] in labels)
    kind,status=stage['status_kind'],stage['status_value']
    need(type(kind) is str and kind in ('absent','exit','signal','other'))
    if kind in ('absent','other'):need(status is None)
    else:need(type(status) is int and ((0<=status<=255) if kind=='exit' else (1<=status<=64)))
    verified=(stage['group_signal']!='Unverified' and stage['group_absence']=='OriginalGroupAbsentObserved'
              and stage['direct_child']=='Reaped' and kind!='absent')
    # Bits: 1 stack marker, 2 panic header, 4 allocation marker, 8 fatal runtime marker.
    # Lexical observations only: neither an empty mask nor incomplete capture
    # establishes an abort cause. Process custody is required before disclosure.
    fatal=stage['fatal_observation']
    need(type(fatal) is dict and set(fatal)=={'state','observed_bits'})
    if verified:
        need(type(fatal['state']) is str and fatal['state'] in ('complete','incomplete')
             and type(fatal['observed_bits']) is int and 0<=fatal['observed_bits']<=15)
    else:
        need(fatal['state']=='withheld' and fatal['observed_bits'] is None)
    expected_status=((process=='sigkill' and stage['group_signal']=='SentWhileLeaderOwned'
                      and kind=='signal' and status==9) or (process=='success' and kind=='exit' and status==0))
    reason=value['reason']
    if reason=='process_cleanup_unverified':need(not verified)
    elif reason=='expected_process_status':need(verified and not expected_status)
    elif reason=='stage_deadline':need(verified and expected_status)
    if reason!='stage_outcome_error':need(value['io_kind']=='other')
    state,primary=stage['diagnostic_state'],stage['private_fixed_primary']
    financial=stage['financial_first_failure']
    need(type(state) is str and state in ('validated','withheld','unavailable')
         and ((state=='validated')==(primary is not None or financial is not None)))
    need(verified or state=='withheld')
    if primary is not None:
        need(verified and type(primary) is dict and set(primary)==PRIVATE_FIXED_PRIMARY_FIELDS)
        for key,labels in (('operation',PRIVATE_FIXED_OPERATIONS),('site',PRIVATE_FIXED_SITES),('engine_code',PRIVATE_FIXED_ENGINE_CODES),('family',PRIVATE_FIXED_FAMILIES)):
            need(type(primary[key]) is str and primary[key] in labels)
        need(type(primary['cause']) is str and primary['cause'] in PRIVATE_FIXED_FAMILIES[primary['family']])
        need(primary['family']!='Engine' or primary['engine_code']!='NotApplicable')
    delivery=stage['delivery_first_failure']
    if delivery is not None:
        need(verified and type(delivery) is dict and set(delivery)=={'boundary','outcome'})
        need(type(delivery['boundary']) is str and delivery['boundary'] in FAILURE_DELIVERY_BOUNDARIES
             and type(delivery['outcome']) is str and delivery['outcome'] in FAILURE_DELIVERY_OUTCOMES)
    if financial is not None:
        need(verified and type(financial) is dict and set(financial)=={'stage','component','error_class','commit_state'})
        for key,labels in (('stage',FINANCIAL_STAGES),('component',FINANCIAL_COMPONENTS),
                           ('error_class',FINANCIAL_ERRORS),('commit_state',FINANCIAL_COMMIT_STATES)):
            need(type(financial[key]) is str and financial[key] in labels)
    return value

class TestOutput:
    """Only one exact native receipt plus the actual one-test harness result."""
    def __init__(self, case):
        need(case in CASES,'selector')
        self.case,self.receipt,self.named,self.summary = case,None,0,0
        self.native_failure=None
    def line(self, line):
        need(type(line) is bytes and len(line) <= MAX_LINE,'output_limit')
        line = line.rstrip(b'\r')
        prefix=b'test '+CASES[self.case].encode()+b' ... '
        if line.startswith(prefix):
            self.named+=1;line=line[len(prefix):]
        elif line.startswith(b'test ') and not line.startswith(b'test result:'):
            raise Rejected('selector')
        if line.startswith(NATIVE_FAILURE_MARKER):
            need(self.native_failure is None)
            self.native_failure=native_failure(self.case,line[len(NATIVE_FAILURE_MARKER):])
        for case, marker in NATIVE_MARKERS.items():
            if line.startswith(marker):
                need(case == self.case and self.receipt is None)
                self.receipt = native_receipt(case,line[len(marker):])
        if line.startswith(b'test result:'):
            need(re.fullmatch(rb'test result: ok\. 1 passed; 0 failed; 0 ignored; 0 measured; [0-9]{1,6} filtered out; finished in [0-9]{1,4}\.[0-9]{2}s',line) is not None,'native_assertion')
            self.summary += 1
    def finish(self, status):
        need(type(status) is int and status == 0,'native_assertion')
        need(self.native_failure is None,'native_assertion')
        need(self.named == self.summary == 1 and self.receipt is not None,'selector')
        need(native_passed(self.case,self.receipt),'native_assertion')
        return self.receipt

def candidate(case, source, receipt):
    return dict(schema=1,profile=PROFILE,source=source,case=case,native_receipt=receipt,
                test_exit=0,owned_test_reaped=True,namespace_processes_absent=True,fixture_directory_absent=True)

def validate_candidate(value, case, source):
    need(type(value) is dict and set(value)=={'schema','profile','source','case','native_receipt',
         'test_exit','owned_test_reaped','namespace_processes_absent','fixture_directory_absent'})
    need(type(value['schema']) is int and value['schema']==1 and value['profile']==PROFILE
         and value['source']==source and value['case']==case)
    receipt=native_receipt(case,json.dumps(value['native_receipt'],separators=(',',':')).encode())
    need(native_passed(case,receipt) and type(value['test_exit']) is int and value['test_exit']==0)
    need(all(value[k] is True for k in ('owned_test_reaped','namespace_processes_absent','fixture_directory_absent')))
    return value

class RuntimeRecords:
    def __init__(self,case,source): self.case,self.source,self.result,self.failure=case,source,None,None
    def __call__(self,line):
        marker=b'CI_FINANCIAL_DURABLE_CANDIDATE '
        if line.startswith(marker):
            need(self.result is None and self.failure is None)
            self.result=validate_candidate(loads(line[len(marker):]),self.case,self.source)
        elif line.startswith(b'CI_FINANCIAL_DURABLE_FAILURE '):
            need(self.failure is None and self.result is None)
            value=loads(line[len(b'CI_FINANCIAL_DURABLE_FAILURE '):])
            fields={'schema','profile','case','code','native_receipt','cleanup_unverified'}
            need(type(value) is dict and set(value) in (fields,fields|{'native_failure'})
                 and type(value['schema']) is int and value['schema']==1 and value['profile']==PROFILE
                 and value['case']==self.case and value['code'] in FAILURES
                 and type(value['cleanup_unverified']) is bool)
            if value['native_receipt'] is not None:
                native_receipt(self.case,json.dumps(value['native_receipt'],separators=(',',':')).encode())
            if 'native_failure' in value:
                native_failure(self.case,json.dumps(value['native_failure'],separators=(',',':')).encode())
            self.failure=value
        else: need(False)
    def finish(self,status):
        need(type(status) is int and status==0 and self.failure is None and self.result is not None,'native_assertion')
        return self.result

def run_case(case, manifest, original_deadline_ns):
    """PID1-only after verified root setup and permanent identity/cap drop."""
    process=None; root=None; first=None; receipt=None; output=None; cleanup_unverified=True
    try:
        need(case in CASES,'selector')
        need(os.getpid()==1 and os.getresuid()==(10001,)*3 and os.getresgid()==(10001,)*3
             and not os.getgroups() and manifest['profile']==PROFILE,'context')
        root=pathlib.Path('/ci-fixture')/({'durable-resume':'a','durable-started':'b'}[case]);root.mkdir(mode=0o700)
        deadline=original_deadline_ns/1e9
        need(time.monotonic()<deadline,'timeout')
        executable=pathlib.Path('/opt/ci-financial')/ROLE
        output=TestOutput(case)
        try:
            process=subprocess.Popen([str(executable),'--exact',CASES[case],'--ignored','--nocapture',
                '--test-threads=1','--color=never'],stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,close_fds=True,start_new_session=True,
                env={'PATH':'/usr/bin:/bin','TMPDIR':str(root),'LANG':'C.UTF-8','RUST_BACKTRACE':'0'})
        except OSError: raise Rejected('start') from None
        need(os.getpgid(process.pid)==process.pid,'start')
        total=0;pending=bytearray()
        with selectors.DefaultSelector() as selector:
            selector.register(process.stdout,selectors.EVENT_READ)
            while True:
                left=deadline-time.monotonic();need(left>0,'timeout')
                events=selector.select(left);need(events,'timeout')
                chunk=os.read(process.stdout.fileno(),32768)
                if not chunk:break
                total+=len(chunk);need(total<=MAX_OUTPUT,'output_limit');pending.extend(chunk)
                while b'\n' in pending:
                    line,_,tail=pending.partition(b'\n');pending=bytearray(tail);output.line(bytes(line))
                need(len(pending)<=MAX_LINE,'output_limit')
        need(not pending)
        receipt=output.finish(process.wait(timeout=max(.001,deadline-time.monotonic())))
        process.stdout.close()
        need(not list(root.iterdir()),'cleanup');root.rmdir()
        need({int(p.name) for p in pathlib.Path('/proc').iterdir() if p.name.isdecimal()}=={1},'cleanup')
        cleanup_unverified=False
        print('CI_FINANCIAL_DURABLE_CANDIDATE '+json.dumps(candidate(case,manifest['source_commit'],receipt),sort_keys=True,separators=(',',':')),flush=True)
        return 0
    except BaseException as error:
        receipt=output.receipt if output is not None else None
        first=error.code if isinstance(error,Rejected) else ('timeout' if isinstance(error,subprocess.TimeoutExpired) else 'internal')
    finally:
        if first is not None and process is not None:
            # Before wait/reap, this parent still owns the leader identity. On
            # any uncertainty the outer container owner destroys the namespace.
            try:
                if process.returncode is None: os.killpg(process.pid,signal.SIGKILL)
            except ProcessLookupError: pass
            except BaseException: cleanup_unverified=True  # Never overwrite the initiating failure.
            try: process.wait(timeout=5)
            except BaseException: cleanup_unverified=True  # Never overwrite the initiating failure.
            try: process.stdout.close()
            except BaseException: cleanup_unverified=True  # Never overwrite the initiating failure.
    failure=dict(schema=1,profile=PROFILE,case=case if case in CASES else 'invalid',code=first or 'internal',native_receipt=receipt,cleanup_unverified=cleanup_unverified)
    if output is not None and output.native_failure is not None:failure['native_failure']=output.native_failure
    print('CI_FINANCIAL_DURABLE_FAILURE '+json.dumps(failure,sort_keys=True,separators=(',',':')),flush=True)
    return 1
