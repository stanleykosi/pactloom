#!/usr/bin/env python3
"""Bounded, public-only output for two fixed synthetic test selections.

Unknown runtime text is discarded, never written to a log. Outer timeout cannot
establish descendant cleanup; the Rust owner is the actual cleanup producer.
"""
import json
import os
import pathlib
import re
import resource
import select
import subprocess
import sys
import time

PREFIX = 'host::manual_enrollment::command::roster_publication_v2::sequential_construction_v3::qualification::'
TESTS = {
    'durable-fixed-signing': (PREFIX + 'durable_proposal_v1::durable_proposal_native_fixed_signing_retains_exact_results', 1080),
    'durable-owner-reopen': (PREFIX + 'durable_proposal_v1::durable_proposal_native_owner_reopen_retains_exact_fixed_proof', 1080),
    'initial': (PREFIX + 'initial_joined_v3::actual_three_born_initial_roster_publications_preserve_refusal', 300),
    'full': (PREFIX + 'full_payment_inputs_v1::actual_three_born_full_payment_uses_one_original_synthetic_path', 1080),
}
PURE_TESTS = tuple(PREFIX + suffix for suffix in (
    'owned_test_process_group_v1::pure_tests::pure_cleanup_orders_one_signal_before_reap_then_only_observation',
    'owned_test_process_group_v1::pure_tests::pure_cleanup_never_observes_or_resignals_after_failed_or_expired_reap',
    'owned_test_process_group_v1::pure_tests::pure_cleanup_uncertain_or_reused_group_is_not_success',
    'owned_test_process_group_v1::pure_tests::pure_cleanup_does_not_hide_an_unverified_signal',
    'owned_test_process_group_v1::pure_tests::pure_cleanup_lost_child_ownership_never_signals_numeric_group',
    'owned_test_process_group_v1::pure_tests::pure_wait_policy_requires_default_without_automatic_reaping',
    'owned_test_process_group_v1::pure_tests::pure_unsupported_or_unknown_wait_policy_never_calls_spawn',
    'owned_test_process_group_v1::pure_tests::pure_live_child_with_unsafe_or_unknown_policy_never_signals_and_retains_root',
    'synthetic_provider_tls_v1::owned_tls_child_v1::pure_tests::pure_tls_original_preparation_cutoff_is_not_cleanup_grace',
    'synthetic_provider_tls_v1::owned_tls_child_v1::pure_tests::pure_tls_stop_plan_never_signals_missing_or_auto_reaped_anchor',
    'synthetic_provider_tls_v1::owned_tls_child_v1::pure_tests::pure_tls_exited_child_needs_only_exact_reap_never_a_signal',
    'process_containment_v1::pure_tests::pure_core_limit_requires_known_zero',
    'process_containment_v1::pure_tests::pure_core_route_has_only_file_pipe_or_unknown_classification',
    'public_outcome_v1::tests::public_outcome_allowlist_maps_exact_values_without_upstream_identifiers',
    'public_outcome_v1::tests::public_outcome_refuses_mismatched_or_claimed_real_success',
    'public_outcome_v1::tests::public_outcome_parser_denies_unknown_truncated_and_noncanonical_records',
    'public_outcome_v1::tests::public_outcome_sidecar_is_single_create_exact_bounded_and_private',
    'public_outcome_v1::tests::public_outcome_sidecar_denies_symlink_multilink_partial_and_oversize',
))
POLICY_ENVELOPE_TESTS = tuple(PREFIX + 'retained_joined_v3::original_policy_export_v2::tests::' + name for name in (
    'producer_shaped_policy_envelope_projects_only_validated_original',
    'policy_envelope_rejects_individually_valid_substituted_originals',
    'policy_envelope_refuses_bare_legacy_unknown_and_duplicate_fields',
))
PROMPT_RENDERING_TESTS = tuple(PREFIX + name for name in (
    'finite_prompt_rendering_preserves_exact_terminal_purpose',
    'full_finite_prompt_census_uses_only_exact_rendered_expectations',
))
LOWER_ERROR_TESTS = ('host::synthetic_roster_trace_v1::lower_error_projection_preserves_only_closed_kinds',)
DENIAL_TESTS = ('host::synthetic_roster_trace_v1::denial_projection_preserves_single_evaluation_and_short_circuit',)
ROLLING_TRANSCRIPT_TESTS = tuple(PREFIX + 'rolling_transcript_v1::tests::' + name for name in (
    'actual_full_input_markers_fit_the_fixed_metadata_bound',
    'consumed_reviews_compact_without_replaying_old_prompts',
    'compaction_erases_discarded_populated_storage',
    'paths_require_complete_exact_markers_and_original_scope',
    'batched_paths_are_latest_before_prompt_and_each_one_use',
    'utf8_partial_waits_but_malformed_bytes_refuse',
    'only_closed_last_diagnostics_survive_private_text_compaction',
    'diagnostic_history_counts_entries_not_physical_line_groups',
    'aggregate_budget_includes_paths_and_closed_history',
    'one_unconsumed_review_still_cannot_exceed_original_bound',
))
AUTHORITY_PROJECTION_TESTS = (PREFIX + 'safe_diagnostics_v1::authority_error_projection_preserves_only_closed_variants',)
HISTORY_MEASUREMENT_TESTS = tuple(PREFIX + 'safe_diagnostics_v1::' + name for name in (
    'history_measurement_parser_requires_exact_bounded_fields',
    'history_server_measurement_projection_preserves_null_zero_and_caps',
    'history_measurement_capture_is_canonical_bounded_and_sticky',
    'history_measurement_parser_preserves_unavailable_and_exhausted',
))
HISTORY_TRANSCRIPT_TESTS = tuple(PREFIX + 'rolling_transcript_v1::tests::' + name for name in (
    'history_measurements_survive_split_lines_and_compaction_without_raw_text',
    'history_measurement_copies_yield_before_original_chunk_budget',
    'history_measurement_copies_yield_before_original_metadata_budget',
))
ADMISSION_PROJECTION_TESTS = tuple(PREFIX + 'safe_diagnostics_v1::' + name for name in (
    'admission_parser_requires_every_exact_field_and_rejects_duplicates',
    'admission_parser_preserves_unavailable_zero_and_commit_uncertainty',
    'admission_parser_rejects_out_of_bounds_and_type_confused_scalars',
    'admission_capture_slots_are_independent_sticky_and_bounded',
))
ADMISSION_TRANSCRIPT_TESTS = tuple(PREFIX + 'rolling_transcript_v1::tests::' + name for name in (
    'admission_diagnostics_survive_split_lines_and_compaction',
    'admission_optional_copies_yield_to_original_chunk_budget',
    'admission_optional_copies_yield_to_original_metadata_budget',
))
FLOW_PROJECTION_TESTS = tuple(PREFIX + 'safe_diagnostics_v1::durable_flow_projection::tests::' + name for name in ('durable_flow_maximal_canonical_record_fits_fixed_slot', 'durable_flow_maximal_error_pair_is_closed', 'durable_flow_maximal_component_lengths', 'durable_flow_payload_cap_exact_boundary', 'durable_flow_getter_labels_are_closed', 'durable_flow_parser_requires_exact_scopes', 'durable_flow_parser_rejects_invalid_categories_and_bounds', 'durable_flow_null_completion_and_measurement_consistency', 'durable_flow_capture_is_sticky_bounded_and_independent'))
FLOW_TRANSCRIPT_TESTS = tuple(PREFIX + 'rolling_transcript_v1::tests::' + name for name in ('durable_flow_survives_split_lines_and_compaction', 'durable_flow_optional_copy_yields_to_original_chunk_budget', 'durable_flow_optional_copy_yields_to_original_metadata_budget'))
FLOW_HOST_TESTS = (PREFIX + 'durable_proposal_v1::worker::admission_diagnostic_tests::pure_flow_stages_are_never_reported_as_admission_or_history',)
ADMISSION_HOST_TESTS = (PREFIX + 'durable_proposal_v1::worker::admission_diagnostic_tests::pure_admission_boundary_routing_preserves_context',)
READ_WAVE_TESTS = tuple(PREFIX + 'observed_joined_v3::' + name for name in (
    'actual_read_wave_prepares_every_item_before_original_order_execution',
    'failed_read_wave_drops_prepared_values_without_execution_or_retry',
))
AUTHORITY_RENDERER_TESTS = (
    'native_witness_owner::window::ephemeral_fixture_v1::public_control_navigation_v1::tests::wheel_navigation_reaches_actual_disabled_controls_without_mutating_form',
    'native_witness_owner::window::ephemeral_fixture_v1::public_control_navigation_v1::tests::missing_exact_control_stops_after_finite_wheel_events',
    'native_witness_owner::window::ephemeral_fixture_v1::public_control_navigation_v1::tests::exact_label_requires_visible_clip_and_viewport',
    'native_witness_owner::window::ephemeral_fixture_v1::public_control_navigation_v1::tests::retained_receipt_scroll_is_independent_of_actual_selection_navigation',
    'native_witness_owner::window::ephemeral_fixture_v1::public_control_navigation_v1::tests::same_parent_scroll_areas_use_distinct_stable_production_ids',
    'native_witness_owner::window::ephemeral_fixture_v1::public_control_navigation_v1::tests::qualified_area_requires_sizing_then_actual_focused_primary_click',
)
AUTHORITY_VALIDATION_TESTS = ('manual_roster_construction_v3::validation_reuse_tests::call_local_validation_preserves_complete_records_and_canonical_identifiers', 'manual_roster_construction_v3::validation_reuse_tests::call_local_validation_rejects_substituted_plan_extension_attempt_and_amounts', 'manual_roster_construction_v3::validation_reuse_tests::call_local_validation_keeps_every_consume_join_and_revalidates_each_call')
SIGNER_LINEAGE_PREDICATE_TESTS = tuple(
    'native_ui::born_manual_roster_v2::common_context_reentry::lineage_comparison_tests::' + name
    for name in (
        'exact_lineage_comparison_refuses_another_well_formed_digest',
        'same_call_lineage_probe_preserves_both_sentinel_originals',
    )
)

SIGNER_TIMING_TESTS = tuple(
    'native_ui::born_manual_roster_v2::synthetic_timing_v1::tests::' + name
    for name in (
        'aggregate_counts_only_returned_results_and_keeps_incomplete',
        'aggregate_saturation_is_bounded_and_marked_invalid',
        'aggregate_catalogue_is_fixed_and_unselected_operations_are_inert',
    )
)
TIMING_HOST_TESTS = tuple('host::synthetic_roster_timing_v1::tests::' + name for name in (
    'timing_records_keep_incomplete_and_failed_spans_distinct',
    'timing_capture_refuses_unknown_duplicate_and_out_of_bound_data',
    'timing_stream_framing_discards_oversized_lines_and_erases_partial_bytes',
    'timing_aggregate_bounds_do_not_sum_nested_durations',
    'timing_complete_dump_is_not_success_or_finished_work',
))
TIMING_LANDMARK_PHASES = (
    'ObservedReadRequest','ObservedReadAdmitted','ObservedReadOpen','ObservedReadPair',
    'ObservedReadFinish','ObservedReadPark','ObservedBarrier','ConstructedPendingReview',
    'ConstructedConsume','ConstructedSignerPark','ConstructedServerSeal','ConstructedCheckpoint',
    'CompletionReentryFinish','CompletionConstructionFinish','CheckpointEngine',
)
TIMING_ALL_PHASES = frozenset(('ObservedBarrier','ConstructedCheckpoint','CheckpointEngine'))
TIMING_LANDMARK_SLOTS = tuple((phase,ordinal) for phase in TIMING_LANDMARK_PHASES
    for ordinal in (('All',) if phase in TIMING_ALL_PHASES else ('First','Second')))
TIMING_AGGREGATE_PHASES = (
    'CompletionClaimCheck','CompletionClaimSign','CompletionClaimGranted','CompletionClaimClaim',
    'CompletionClaimClaimed','CompletionClaimObserve','CompletionClaimHistory','CompletionClaimReentered',
    'CompletionClaimSend','ConstructionReserve','ConstructionReservedAppend','ConstructionConsume',
    'ConstructionConsumedAppend','ConstructionNamedOwner','ConstructionIntoNamed','ConstructionFinalOwner',
)
TIMING_PREFIX = '[JOINED_TIMING '
HISTORY_MEASUREMENT_PREFIX = '[HISTORY_MEASUREMENT_V1 '
HISTORY_SERVER_MEASUREMENT_PREFIX = '[HISTORY_SERVER_MEASUREMENT_V1 '
HISTORY_DURATION_LIMIT_US = 600000000
HISTORY_COUNT_LIMIT = 1000000
HISTORY_PHASES = frozenset(('Snapshot','Page'))
HISTORY_CHECK_SITES = frozenset(('ReplayInitial','ReplayAfterSnapshot','ReplayBeforePage',
    'ReplayAfterPage','ReplayFinal','ExchangeInitial','BeforeConnect','AfterConnect',
    'BeforeHandshakeIo','AfterHandshake','AfterPeerBinding','AfterRequestBuild',
    'BeforeRequestWrite','AfterRequestWrite','AfterResponseRead'))
HISTORY_CHECKPOINTS = frozenset(('EntryDeadline','DeadlineSelection','ConnectRemaining',
    'BeforeCallback','Callback','AfterCallback','Operation','Validation'))
HISTORY_SELECTED_LIMITS = frozenset(('Caller','Exchange'))
HISTORY_SERVER_POINTS = ('BeforeAdmission','AfterAdmission')
HISTORY_OPTIONAL_DURATIONS = frozenset(('selected_budget_us','caller_remaining_at_budget_start_us',
    'caller_remaining_at_failure_us','selected_remaining_at_failure_us','exchange_elapsed_us'))
HISTORY_COST_COUNTS = frozenset(('callback_calls','connect_calls','handshake_calls',
    'frame_write_calls','frame_read_calls'))
HISTORY_COST_DURATIONS = frozenset(('callback_us','callback_max_us','connect_us','handshake_us',
    'frame_write_us','frame_read_us'))
HISTORY_MEASUREMENT_FIELDS = frozenset(('version','phase','page_ordinal','check_site','checkpoint',
    'selected_limit','history_elapsed_us','pre_budget_callback_calls','pre_budget_callback_us',
    'history_cost','exchange_cost','clamped','incomplete')) | HISTORY_OPTIONAL_DURATIONS
HISTORY_SERVER_MEASUREMENT_FIELDS = frozenset(('version','point','age_us','remaining_us',
    'stopped','finished','clamped'))

# CI14 admission records are separate from the unchanged historical schema.
ADMISSION_PREFIXES = ('[ADMISSION_MEASUREMENT_V1 ','[SIGNER_ADMISSION_V1 ','[WITNESS_ADMISSION_V1 ')
ADMISSION_KINDS = ('admission_measurement','signer_admission','witness_admission')
ADMISSION_INVALID = tuple('CI_SYNTHETIC_'+kind.upper()+' invalid=true details_withheld=true' for kind in ADMISSION_KINDS)
ADMISSION_CHECK_SITES = HISTORY_CHECK_SITES - frozenset(('ReplayInitial','ReplayAfterSnapshot','ReplayBeforePage','ReplayAfterPage','ReplayFinal'))
ADMISSION_MEASUREMENT_FIELDS = (HISTORY_MEASUREMENT_FIELDS - {'page_ordinal','history_elapsed_us','history_cost'}) | {'operation_elapsed_us','operation_cost'}
SIGNER_ADMISSION_FIELDS = frozenset(('version','stage','completion','retention','original_error','callback_stage','measurement'))
SIGNER_ADMISSION_DURATIONS = frozenset(['native_approval_us', 'retention_us', 'submit_preflight_us', 'callback_custody_us', 'callback_custody_max_us', 'request_validation_us', 'request_validation_max_us'])
SIGNER_ADMISSION_COUNTS = frozenset(['callback_custody_calls', 'request_validation_calls'])
SIGNER_ADMISSION_ERRORS = frozenset(['SignerUnavailable', 'SignerPeerLifetimeUnavailable', 'SignerIo', 'SignerAuthentication', 'SignerInvalidData', 'SignerCrypto', 'SignerLocked', 'SignerBackupRequired', 'SignerRecoveryRequired', 'SignerAlreadyOpen', 'SignerReviewMismatch', 'SignerVerification', 'SignerUncertain', 'SignerConsentJournal', 'SignerStore'])
ADMISSION_AUTHORITY_ERRORS = frozenset(['AuthorityInvalidBinding', 'AuthorityPermission', 'AuthorityStaleHead', 'AuthorityConflict', 'AuthorityInactive', 'AuthorityRecoveryRequired', 'AuthorityExpired', 'AuthorityPolicyDenied', 'AuthorityBudgetExceeded', 'AuthorityInputReserved', 'AuthorityObligationReserved', 'AuthorityLimit', 'AuthorityStorage', 'AuthorityCorruptHistory', 'AuthorityPermanentStopUnavailable', 'AuthorityOfflineHistoryUnsupported', 'AuthorityConstructionHistoryUnsupported', 'AuthorityUnsupportedVersion', 'AuthorityAuthentication', 'AuthorityUncertain', 'AuthorityResolutionUnavailable', 'AuthoritySessionRequired', 'AuthoritySessionPending'])
WITNESS_ADMISSION_SPANS = frozenset(['worker', 'source_arm', 'server_create', 'accept', 'connection', 'handshake', 'frame_read', 'dispatch', 'publication', 'append', 'commit', 'frame_write', 'fixture_finish'])
SIGNER_ADMISSION_STAGES = frozenset(['FixtureState', 'ReviewCorrelation', 'NativeApproval', 'IntentRetention', 'SubmitCustody', 'SubmitIntent', 'SubmitInterval', 'SubmitWorkspace', 'AuthorityCall', 'WorkerCompletion', 'CommittedCorrelation'])
SIGNER_ADMISSION_COMPLETIONS = frozenset(['NotObserved', 'ReturnedOk', 'ReturnedErr', 'Missing', 'Invalidated', 'Disconnected'])
SIGNER_ADMISSION_RETENTIONS = frozenset(['NotObserved', 'Unconfirmed', 'Confirmed'])
SIGNER_ADMISSION_CALLBACK_STAGES = frozenset(['WorkspaceCurrent', 'Custody', 'RequestValidation'])
WITNESS_ADMISSION_STAGES = frozenset(['SourceArm', 'ServerCreate', 'ListenerAccept', 'ResultLookup', 'SocketBinding', 'WaitCurrent', 'TlsSetup', 'TlsHandshake', 'PeerBinding', 'FrameRead', 'SemanticDispatch', 'JournalPreflight', 'ExactRequest', 'Publication', 'Apply', 'Append', 'FinalCurrent', 'Commit', 'ControlledResult', 'SnapshotRecord', 'OutputCheck', 'FrameWrite', 'CloseFlush', 'WorkerDisplay', 'FixtureDrain', 'FixtureReceipt', 'FixtureCorrelation'])
WITNESS_ADMISSION_ATTRIBUTIONS = frozenset(['SelectedServer', 'ExactRequest'])
WITNESS_ADMISSION_RESULTS = frozenset(['NotObserved', 'ReturnedOk', 'ReturnedErr'])
WITNESS_ADMISSION_COMPLETIONS = frozenset(['NotObserved', 'Received', 'Disconnected', 'Panicked'])
WITNESS_ADMISSION_COMMITS = frozenset(['NotObserved', 'Entered', 'ReturnedOk', 'ReturnedErr'])
WITNESS_ADMISSION_RECEIPT_GATES = frozenset(['NotObserved', 'Unfocused', 'EpochMismatch', 'Revoked', 'Closing', 'ClockRejected', 'Retained'])
WITNESS_ADMISSION_CORRELATIONS = frozenset(['NotObserved', 'Matched', 'Rejected'])
ADMISSION_IO_KINDS = frozenset(['Timeout', 'Closed', 'Refused', 'Other'])
SIGNER_ADMISSION_MEASUREMENT_FIELDS = SIGNER_ADMISSION_DURATIONS | SIGNER_ADMISSION_COUNTS | {'clamped','incomplete'}
WITNESS_ADMISSION_FIELDS = frozenset(('version','first_semantic','first_connection','worker_result','fixture_result','worker_error','fixture_error','worker_stage','fixture_stage','completion','commit','controlled_result','snapshot_recorded','receipt_gate','final_correlation','cost','clamped','incomplete'))
WITNESS_ADMISSION_ERROR_FIELDS = frozenset(('stage','attribution','io_kind','error'))

# One bounded failure-only Flow slot. Existing History/Admission schemas stay closed.
FLOW_PRIVATE_PREFIX = '[DURABLE_FLOW_V1 '
FLOW_PREFIX = 'CI_SYNTHETIC_DURABLE_FLOW '
FLOW_INVALID = 'CI_SYNTHETIC_DURABLE_FLOW invalid=true details_withheld=true'
FLOW_FIELDS = ('version', 'operation', 'first_error', 'terminal_error', 'fixture_result', 'completion', 'call_outcomes', 'lower_call_measurement', 'clamped', 'incomplete')
FLOW_MEASUREMENT_FIELDS = ('phase', 'check_site', 'checkpoint', 'selected_limit', 'selected_budget_us', 'caller_remaining_at_budget_start_us', 'caller_remaining_at_failure_us', 'selected_remaining_at_failure_us', 'operation_elapsed_us', 'exchange_elapsed_us', 'pre_budget_callback_calls', 'pre_budget_callback_us', 'operation_cost', 'exchange_cost', 'clamped', 'incomplete')
FLOW_CALL_FIELDS = ('writer_acquire', 'writer_activate', 'active_verify', 'reconciliation', 'session_invalidation', 'release', 'request_retention', 'reservation', 'permit_retention', 'key_use', 'result_retention')
FLOW_COST_FIELDS = ('callback_calls', 'callback_us', 'callback_max_us', 'connect_calls', 'connect_us', 'handshake_calls', 'handshake_us', 'frame_write_calls', 'frame_write_us', 'frame_read_calls', 'frame_read_us')
FLOW_OPERATION = frozenset(('WriterReconcile', 'FinancialImport', 'InitialSign', 'RetainedRetry', 'ResultService'))
FLOW_STAGE = frozenset(('FixtureState', 'AcquirePrepare', 'AcquireNative', 'AcquireCall', 'ActivationPrepare', 'ActivationNative', 'ActivationCall', 'ActiveVerification', 'ReconcilePrepare', 'ReconcileNative', 'ReconcileCall', 'Invalidate', 'ImportReceive', 'ImportPairing', 'ImportSource', 'WalletSync', 'WalletSource', 'WitnessHead', 'SpendStage', 'DisclosureDecision', 'SpendDecision', 'SigningLaunch', 'AuthorizationSource', 'Release', 'RequestRetain', 'Reserve', 'PermitRetain', 'WalletGuard', 'KeyUse', 'Derive', 'Sign', 'VerifySigned', 'ResultRetain', 'RetainedLookup', 'RetryInvariant', 'Completion', 'ResultService', 'Close'))
FLOW_ERROR_DOMAIN = frozenset(('Signer', 'Bridge', 'Authority', 'Journal', 'WalletKeyUse', 'Store'))
FLOW_JOB_PURPOSE = frozenset(('AcquirePrepare', 'Acquire', 'ActivationPrepare', 'Activate', 'ReconcilePrepare', 'Reconcile', 'Import', 'WalletReview', 'Sign', 'ResultService'))
FLOW_RESULT = frozenset(('NotObserved', 'ReturnedOk', 'ReturnedErr'))
FLOW_RECEIVE = frozenset(('NotObserved', 'Pending', 'Received', 'Missing', 'Disconnected', 'Invalidated'))
FLOW_PRESENTATION = frozenset(('NotObserved', 'Accepted', 'Suppressed'))
FLOW_CALL_OUTCOME = frozenset(('NotObserved', 'Entered', 'ReturnedOk', 'ReturnedErr'))
FLOW_TRANSPORT_PURPOSE = frozenset(('Acquire', 'Activate', 'Verify', 'Reserve'))
FLOW_TRANSPORT_STAGE = frozenset(('RequestValidation', 'Binding', 'Session', 'CallerDeadline', 'ExchangeDeadline', 'SourceCallback', 'Connect', 'Handshake', 'PeerBinding', 'RequestBuild', 'RequestWrite', 'ResponseRead', 'Response', 'SnapshotValidation', 'ReceiptValidation', 'CommittedHeadValidation', 'FinalValidation', 'Bounds'))
FLOW_AUTHORITY_CODE = frozenset(('InvalidBinding', 'Permission', 'StaleHead', 'Conflict', 'Inactive', 'RecoveryRequired', 'Expired', 'PolicyDenied', 'BudgetExceeded', 'InputReserved', 'ObligationReserved', 'Limit', 'Storage', 'CorruptHistory', 'PermanentStopUnavailable', 'OfflineHistoryUnsupported', 'ConstructionHistoryUnsupported', 'UnsupportedVersion', 'Authentication', 'Uncertain', 'ResolutionUnavailable', 'SessionRequired', 'SessionPending'))
FLOW_CALLBACK_STAGE = frozenset(('WorkspaceCurrent', 'CallerCurrent'))
FLOW_DOMAIN_CODES = {'Signer': frozenset({'BackupRequired', 'Unavailable', 'PeerLifetimeUnavailable', 'Crypto', 'Locked', 'AlreadyOpen', 'ReviewMismatch', 'Verification', 'ConsentJournal', 'Store', 'RecoveryRequired', 'Authentication', 'InvalidData', 'Uncertain', 'Io'}), 'Bridge': frozenset({'Authority', 'Permission', 'Journal', 'CompleteOriginRecoveryUnavailable', 'Ipc', 'SignerOriginUnavailable', 'Verification', 'Missing', 'Wallet', 'RecoveryRequired', 'Conflict', 'Uncertain', 'Limit', 'Binding'}), 'Authority': frozenset({'Permission', 'Inactive', 'SessionRequired', 'RecoveryRequired', 'StaleHead', 'Conflict', 'Limit', 'ObligationReserved', 'Storage', 'OfflineHistoryUnsupported', 'BudgetExceeded', 'SessionPending', 'Uncertain', 'ConstructionHistoryUnsupported', 'Expired', 'Authentication', 'PermanentStopUnavailable', 'ResolutionUnavailable', 'InputReserved', 'InvalidBinding', 'PolicyDenied', 'CorruptHistory', 'UnsupportedVersion'}), 'Journal': frozenset({'Storage', 'Permission', 'ConstructionHistoryUnsupported', 'Database', 'Expired', 'OfflineHistoryUnsupported', 'NotFound', 'UnsupportedSchema', 'BudgetExceeded', 'RecoveryRequired', 'Conflict', 'LiveAuthorization', 'Limit', 'InputReserved', 'InvalidBinding', 'NamedRecipientHistoryUnsupported'}), 'WalletKeyUse': frozenset({'Storage', 'Permission', 'Expiry', 'Sync', 'Policy', 'RecoveryRequired', 'SelectionExpired', 'StateChanged'}), 'Store': frozenset({'Encoding', 'Database', 'RevisionConflict', 'ResourceExhausted', 'NotFound', 'UnsupportedSchema', 'InvalidInput', 'BudgetExceeded', 'StorageSecurity', 'RecoveryRequired', 'WriterEpochMismatch', 'LiveAuthorizationExists', 'IdempotencyConflict', 'AlreadyExists', 'InvalidTransition', 'Poisoned', 'InputReserved', 'File'})}
FLOW_NESTED_CODES = {('Signer', 'ConsentJournal'): frozenset({'JournalNotFound', 'JournalUnsupportedSchema', 'JournalNamedRecipientHistoryUnsupported', 'JournalConstructionHistoryUnsupported', 'JournalDatabase', 'JournalInvalidBinding', 'JournalStorage', 'JournalRecoveryRequired', 'JournalLimit', 'JournalOfflineHistoryUnsupported', 'JournalBudgetExceeded', 'JournalPermission', 'JournalExpired', 'JournalLiveAuthorization', 'JournalInputReserved', 'JournalConflict'}), ('Bridge', 'Journal'): frozenset({'JournalNotFound', 'JournalUnsupportedSchema', 'JournalNamedRecipientHistoryUnsupported', 'JournalConstructionHistoryUnsupported', 'JournalDatabase', 'JournalInvalidBinding', 'JournalStorage', 'JournalRecoveryRequired', 'JournalLimit', 'JournalOfflineHistoryUnsupported', 'JournalBudgetExceeded', 'JournalPermission', 'JournalExpired', 'JournalLiveAuthorization', 'JournalInputReserved', 'JournalConflict'}), ('Signer', 'Store'): frozenset({'StoreIdempotencyConflict', 'StoreUnsupportedSchema', 'StoreRecoveryRequired', 'StoreLiveAuthorizationExists', 'StoreInvalidTransition', 'StoreAlreadyExists', 'StoreStorageSecurity', 'StoreNotFound', 'StoreInvalidInput', 'StoreInputReserved', 'StoreEncoding', 'StoreWriterEpochMismatch', 'StoreFile', 'StoreResourceExhausted', 'StoreDatabase', 'StoreBudgetExceeded', 'StorePoisoned', 'StoreRevisionConflict'}), ('Bridge', 'Authority'): frozenset({'AuthorityStorage', 'AuthorityBudgetExceeded', 'AuthorityInvalidBinding', 'AuthorityPermanentStopUnavailable', 'AuthorityStaleHead', 'AuthorityConstructionHistoryUnsupported', 'AuthorityUnsupportedVersion', 'AuthorityObligationReserved', 'AuthoritySessionPending', 'AuthorityPolicyDenied', 'AuthorityExpired', 'AuthorityLimit', 'AuthorityConflict', 'AuthorityInactive', 'AuthorityAuthentication', 'AuthorityUncertain', 'AuthorityInputReserved', 'AuthorityPermission', 'AuthorityRecoveryRequired', 'AuthorityResolutionUnavailable', 'AuthoritySessionRequired', 'AuthorityOfflineHistoryUnsupported', 'AuthorityCorruptHistory'}), ('Bridge', 'Wallet'): frozenset({'WalletKeyUseRecoveryRequired', 'WalletKeyUseStorage', 'WalletKeyUseSelectionExpired', 'WalletKeyUsePermission', 'WalletKeyUseExpiry', 'WalletKeyUseSync', 'WalletKeyUseStateChanged', 'WalletKeyUsePolicy'}), ('Journal', 'Storage'): frozenset({'StorageSecuritySourceChanged', 'StorageSecurityUnsupportedPlatform', 'StorageSecurityUnsafePath', 'StorageSecurityDatabase', 'StorageSecurityAuthenticationFailed', 'StorageSecurityQuarantinedDatabase', 'StorageSecurityIo', 'StorageSecurityRecoveredGeneration', 'StorageSecurityUnqualifiedRuntime', 'StorageSecurityUninitializedDatabase', 'StorageSecurityGenerationArchive', 'StorageSecurityAlreadyExists', 'StorageSecuritySnapshotLimit', 'StorageSecurityPlaintextRefused', 'StorageSecurityMissingDatabase'}), ('Store', 'StorageSecurity'): frozenset({'StorageSecuritySourceChanged', 'StorageSecurityUnsupportedPlatform', 'StorageSecurityUnsafePath', 'StorageSecurityDatabase', 'StorageSecurityAuthenticationFailed', 'StorageSecurityQuarantinedDatabase', 'StorageSecurityIo', 'StorageSecurityRecoveredGeneration', 'StorageSecurityUnqualifiedRuntime', 'StorageSecurityUninitializedDatabase', 'StorageSecurityGenerationArchive', 'StorageSecurityAlreadyExists', 'StorageSecuritySnapshotLimit', 'StorageSecurityPlaintextRefused', 'StorageSecurityMissingDatabase'}), ('WalletKeyUse', 'Sync'): frozenset({'SyncResourceLimit', 'SyncInterrupted', 'SyncNoCurrentObservation', 'SyncInvalidResponse', 'SyncChain', 'SyncReconciliationRequired', 'SyncWallet', 'SyncInvalidRequest', 'SyncAccessDenied'})}
FLOW_ERROR_FIELDS = ('stage','domain','code','nested_code')
FLOW_COMPLETION_FIELDS = ('purpose','result','receive','presentation')
FLOW_LOWER_FIELDS = ('purpose','stage','authority_code','io_kind','callback_stage','measurement')

STORAGE_BOOTSTRAP_TEST = 'recovery_generation::layered::tests::native_layered_current_eight_nine_parent_provenance_is_exact_and_not_relabelable'
SIGNER_VALIDATION_TESTS = (
    'account::birth::retired_historical_tests::birth_identity_one_derivation_preserves_both_original_commitments',
    'account::birth::active::tests::borrowed_original_plaintext_matches_complete_decoder_and_refuses_substitution',
    'account::birth::active::tests::borrowed_original_is_exact_vault_scoped_and_checks_fresh_ciphertexts',
    'account::birth::active::tests::borrowed_original_cannot_be_issued_for_mismatched_held_origin',
)
SIGNER_DURABLE_LABEL_TESTS = ('native_ui::runtime::durable_entry_v1::tests::durable_fixture_pairing_labels_use_existing_identifier_grammar',)
SIGNER_DURABLE_RECEIPT_TESTS = tuple('consent_journal::preconstruction_lease::durable_receipt_tests::' + name for name in ('current_receipts_pass_but_stale_history_does_not_approve_new_disclosure', 'both_receipts_require_exact_current_session_generation_epoch_and_measurement', 'both_receipts_require_an_issued_nonce_not_just_matching_origin_metadata', 'both_receipts_require_the_original_monotonic_review_window', 'both_receipts_require_current_wall_clock_window'))
# This real LocalIpc regression is CI-only, never a pure/validation selection.
SIGNER_DURABLE_ENDPOINT_TEST = 'native_ui::runtime::durable_entry_v1::tests::durable_endpoint_is_external_preserves_inventory_and_drains_before_cleanup'
SIGNER_BOOKKEEPING_TESTS = (
    'account::birth::enrollment::roster_v2::inventory::tests::challenge_bookkeeping_requires_successful_checked_send_first',
    'account::birth::enrollment::roster_v2::inventory::candidate::tests::candidate_nonce_is_retained_only_after_fully_checked_send_success',
)
SIGNER_PRECONSTRUCTION_TESTS = tuple(
    'account::birth::enrollment::roster_v2::continuation::preconstruction::tests::' + name
    for name in (
        'approval_history_keeps_original_attempt_and_legacy_refusal',
        'exposure_and_tampered_approval_history_remain_refused',
        'approval_cannot_cross_enrollment_or_original_attempt',
    )
)
SIGNER_BIRTH_LINK_TESTS = tuple(
    'account::birth::history::preconstruction_tests::' + name
    for name in (
        'original_birth_link_accepts_approval_only_and_preserves_legacy_refusal',
        'original_birth_link_rejects_foreign_extension_and_other_original',
        'original_birth_link_rejects_reserved_consumed_and_tampered_history',
    )
)
SIGNER_ENDPOINT_CHANNEL_TESTS = tuple(
    'native_ui::synthetic_born_joined_qualification::construction_fixture::endpoint_report_tests::' + name
    for name in (
        'original_report_requires_transfer_and_is_received_once',
        'missing_or_dropped_report_is_terminal',
        'separate_original_report_channels_cannot_supply_each_other',
        'invalid_report_consumes_the_only_publication_opportunity',
    )
)
SIGNER_SNAPSHOT_STORAGE_TESTS = tuple(
    'consent_journal::common_context_reentry_audit_tests::' + name
    for name in (
        'owner_snapshot_is_fresh_and_never_commits_a_callers_transaction',
        'owner_snapshot_revalidates_changed_payload_and_missing_rows',
    )
)
SIGNER_SHAPE_TAMPER_TESTS = (
    'consent_journal::common_context_reentry_audit_tests::completed_shape_pass_still_rejects_lineage_history_and_reservation_tampering',
)
SIGNER_REENTRY_COMPATIBILITY_TESTS = tuple(
    'consent_journal::common_context_reentry_audit_tests::' + name
    for name in (
        'signed_handoff_reopen_requires_exact_authorized_only_original_journal',
        'signed_handoff_encrypted_six_phase_reopen_is_exact_and_atomic',
        'explicit_v5_keeps_old_bytes_charge_and_never_issues_recovery',
    )
)
SIGNER_CALL_LOCAL_TESTS = tuple(
    'consent_journal::common_context_reentry_audit_tests::' + name
    for name in (
        'call_local_invocation_binding_keeps_every_phase_admission_digest',
        'call_local_invocation_binding_never_survives_signature_read_or_history_changes',
    )
)
SIGNER_AUDIT_STORAGE_TESTS = (
    'consent_journal::common_context_reentry_audit_tests::stored_audit_digests_and_shapes_are_revalidated_on_every_read',
)
SIGNER_AUDIT_COMPATIBILITY_TESTS = tuple(
    'consent_journal::common_context_reentry_audit_tests::' + name
    for name in (
        'signed_handoff_each_missing_local_suffix_stays_charged_and_orphans_fail',
        'signed_handoff_exact_lineage_substitutions_fail_after_complete_validation',
    )
)
SIGNER_NAMED_ORIGIN_SNAPSHOT_TESTS = tuple(
    'consent_journal::common_context_reentry_audit_tests::' + name
    for name in (
        'named_origin_snapshot_matches_complete_reader_and_preserves_outer_transactions',
        'named_origin_snapshot_rechecks_identity_evidence_schema_and_local_rows',
        'named_origin_snapshot_revalidates_changed_consumed_rows_on_every_call',
    )
)
MARKER = 'WHOLEPACT_SYNTHETIC_PUBLIC_OUTCOME_V1='
CORE = re.compile(r'\[JOINED_CORE_POLICY inherited_limit=Zero collector=(File|Pipe|Unknown) process_dumpability=Unchanged crash_copy_absence_verified=false\]')
OPTION_INT = r'(?:None|Some\((?:0|[1-9][0-9]{0,9})\))'
CLEANUP = re.compile(r'\[JOINED_CLEANUP group_signal=(SentWhileLeaderOwned|AlreadyAbsentWhileLeaderOwned|Unverified) group_absence=(OriginalGroupAbsentObserved|Unverified) direct_child=(Reaped|Unverified) root_cleanup=(ClosedAndAbsenceVerified|RetainedForUnverifiedProcess|CloseOrAbsenceUnverified) exit=(' + OPTION_INT + r') signal=(' + OPTION_INT + r') core_dumped=(true|false)\]')
FAILURE = re.compile(r'\[JOINED_FAILURE exit=(' + OPTION_INT + r') signal=(' + OPTION_INT + r') core_dumped=(true|false) inputs=(0|[1-9][0-9]{0,5})/(0|[1-9][0-9]{0,5}) reason=([A-Za-z0-9]+) static_boundaries=([^\]\r\n]+)\]')
# Exact closed labels copied from the same compiled safe_diagnostics_v1.rs.
# The no-process self-tests check equality with those original Rust declarations.
HARNESS_FAILURE_REASONS = frozenset('Unclassified Deadline ChildObservation ChildExit PollIo ReadIo OutputLimit IncompleteUtf8 InvalidUtf8 MultilineInput WriteIo FlushIo MissingPathMarker InvalidPath InvalidChallenge OutcomeRead CleanupUnverified'.split())
BOUNDARIES = frozenset('ObservationClockRollback ObservationClockWallExpired ObservationClockMonotonicExpired ObservationRetainedClockRead ObservationRetainedClockDenied ObservationAdmittedClockRead ObservationAdmittedClockDenied CompletionObservationDenied CompletionPostReentryCurrent CompletionReadBinding CompletionConstructionTime CompletionCallerBinding CompletionConstructionRequest EngineCheckpointClaim EngineCheckpointPlan EngineCheckpointRetained EngineCheckpointParts EngineCheckpointNative EngineCheckpointHeld EngineCheckpointRestriction EngineCheckpointConstruct EngineCheckpointInspect EngineCheckpointActionLimit EngineCheckpointConsent EngineCheckpointReceipt EngineCheckpointRecord EngineCheckpointEnqueue EngineCheckpointFinish EngineCheckpointContext CheckpointEngine CheckpointWalletUnwind CheckpointFinish CheckpointObservations CheckpointOutput CheckpointBeforeClaim CheckpointClaimMayExist SignerPollCancelled SignerPollDeadline SignerPollTerminal RosterConstructionIntoNamed RosterConstructionNamedOwner RosterConstructionFinalOwner RosterConstructionCheck RosterConstructionReserve RosterConstructionReservedAppend RosterConstructionConsume RosterConstructionConsumedAppend RosterConstructionSend ConstructionClockTerminal ConstructionClockLiveness ConstructionClockWallRollback ConstructionClockWallExpired ConstructionClockMonotonicExpired RosterCompletionClaimCheck RosterCompletionClaimSign RosterCompletionClaimGranted RosterCompletionClaimClaim RosterCompletionClaimClaimed RosterCompletionClaimObserve RosterCompletionClaimHistory RosterCompletionClaimReentered RosterCompletionClaimSend NativeOwnerRevoked NativeOwnerExpired NativeOwnerParent NativeOwnerRetirementParent RosterOwnerEpoch RosterWorkOpenCommonContext RosterWorkPrepareCompletionWitness RosterWorkPrepareReenteredConstruction RosterWorkCommitCompletionPair RosterWorkCommitCompletionWitness RosterWorkCommitCompletionClaim RosterWorkCommitReenteredConstruction RosterCompletionWitnessCheck RosterCompletionWitnessHistory RosterCompletionWitnessHistoryBinding RosterCompletionWitnessTransport CompletionOriginal CompletionPairApproval CompletionPairBegin CompletionPairFinish CompletionReentryRequest CompletionRequestApproval CompletionReentryBegin CompletionReentryFinish CompletionConstructionBegin CompletionConstructionFinish RosterBirthHistoryGate RosterBirthExtension RosterBirthOriginal RosterBirthLinkage ContinuationRetainedSource ContinuationAttemptedSource ContinuationWriterSource ContinuationHistoryReplay ContinuationPairing ContinuationPreparedReview ContinuationSource ContinuationBirthLink ContinuationPreconstruction ContinuationHistoryGate ContinuationHistoryArchive ContinuationRetainedReceipt ContinuationPreviousLoad ContinuationProposalCapacity ContinuationProposalIndex ContinuationAttemptSequence ContinuationProposalValidation ObservedPlanWitnessOrigin WitnessPlanInput WitnessPlanSelect WitnessPlanInputUtf8 WitnessPlanPublicRefusal WitnessPlanQualifiedEntry WitnessPlanLaunch WitnessPlanDrain WitnessPlanPending WitnessPlanApprove WitnessPlanReceipt WitnessPlanReceiptDigest WitnessPlanExpectedParse WitnessPlanDigestMatch WitnessPlanWorkerPrepare WitnessPlanWorkerApprove CandidateRetainCurrent CandidateRetainRequest CandidateRetainBegin CandidateRetainFinish CandidateLeaseOrigin CandidateRequestRemaining InventoryLeaseOrigin InventoryRequestSource InventoryRequestProvenance InventoryRequestBinding InventoryRequestRemaining InventorySourceOwner InventorySourceNative InventorySourceDeadline InventorySourcePeer InventorySourceOwnerBinding InventorySourcePeerBinding InventorySourceRetiredGrant InventorySourceProcess InventorySourceRetained InventorySourceAdmission InventorySourceHistory InventorySourceWitness InventoryWindowWallRollback InventoryWindowWallExpired InventoryWindowMonotonicExpired InventoryNativeBinding InventorySourceRequest InventoryPeerConnection InventoryObservedMissing InventoryObservedLifetimeInvalid InventoryObservedWallRollback InventoryObservedSessionExpired InventoryObservedAgeExpired ScanAccessAccount ScanAccessNativeBefore ScanAccessRequest ScanAccessTarget ScanAccessHostAccess ScanAccessPrincipal ScanAccessEnrollmentPrincipal ScanAccessRequestDigest ScanAccessScopeDigest ScanAccessImport ScanAccessNativeAfter ScanNativeAdmissionDeadline ScanNativeLease ScanNativeRemaining ScanNativePurpose ScanNativeAccount ScanNativeProviderSource ScanNativeProviderEndpoint ScanNativeProviderTrust RosterWorkOpen RosterWorkPrepareIntent RosterWorkPrepareReentry RosterWorkPrepareSignature RosterWorkPrepareExport RosterWorkPrepareWitness RosterWorkPrepareAcquire RosterWorkPrepareActivate RosterWorkPreparePublication RosterWorkPrepareServe RosterWorkPrepareContinuationProposal RosterWorkPrepareContinuationSign RosterWorkPrepareContinuationExport RosterWorkPrepareContinuedReentry RosterWorkPrepareContinuedServe RosterWorkPreparePolicyExport RosterWorkPrepareInventory RosterWorkPrepareCandidateSelection RosterWorkRetryAdmission RosterWorkRetryContinuedAdmission RosterWorkRetryAcquire RosterWorkRetryActivate RosterWorkCommitPair RosterWorkCommitRetain RosterWorkCommitReentry RosterWorkCommitSign RosterWorkCommitExport RosterWorkCommitWitness RosterWorkCommitAcquire RosterWorkCommitActivate RosterWorkCommitAdmit RosterWorkCommitPublish RosterWorkCommitServe RosterWorkCommitContinuationProposal RosterWorkCommitContinuationSign RosterWorkCommitContinuationExport RosterWorkCommitContinuedReentry RosterWorkCommitContinuedAdmit RosterWorkCommitContinuedServe RosterWorkCommitPolicyExport RosterWorkCommitInventory RosterWorkCommitCandidateSelection RosterWorkCommitContributionRetention RosterWorkOther RosterWorkReceiveResult RosterWorkAdoptOutput RosterClearFocus RosterClearOwner RosterClearPeer RosterClearInitialStream RosterClearContinuedStream RosterClearReviewExpired RosterDropLateOutput JoinedPairFinish JoinedRequestBegin JoinedLeaseFinish JoinedInventoryCheck JoinedAuditAppend JoinedInventoryRun InventoryPair InventoryRequest InventoryLease InventoryImport InventoryImportRecord InventoryScan InventorySynchronize InventoryInspect InventoryDisplay InventoryFinish CandidateRun CandidatePair CandidateRequest CandidateLease CandidateExclusions CandidateSelect CandidateDisplay CandidateRetain CandidateAttach FullOriginalPolicy RetainedPredecessor RetainedMaterial RetainedEconomics RetainedInvocation RetainedRuntime RetainedProvider RetainedTls RetainedWitness RetainedPolicyRead RetainedPolicyMatch RetainedSelectionFiles ContinuedPredecessor ContinuedObservation ContinuedOriginal ContinuedWait ContinuedPrepare Bootstrap Session PublicRefusal PaymentReceiver AgreementInput AgreementNative WitnessSetup WitnessOrigin SignerStart BirthExport BirthRead BirthEnroll BirthHistory BirthAcknowledge BirthDistinct SinglePrepare SingleOpen SinglePair SingleSubmit SingleExport SingleWitness SinglePublicationPrepare SingleHistory SinglePublicationOpen SinglePublicationPair SingleFinish SingleClose RosterPrepare RosterOpen RosterPair RosterSubmit RosterExport RosterWitness RosterPublicationPrepare RosterHistory RosterPublicationOpen RosterPublicationPair RosterFinish RosterClose MetadataCheck FinancialRefusal EndInvariant SignerCreate SignerExportBirth SignerAcknowledge SignerOpenSingleIntent SignerPollSingleIntent SignerExportSingle SignerOpenSinglePublication SignerPollSinglePublication SignerCloseSinglePublication SignerOpenRosterIntent SignerPollRosterIntent SignerExportRoster SignerOpenRosterPublication SignerPollRosterPublication SignerCloseRosterPublication SignerOpenContinuationIntent SignerPollContinuationIntent SignerOpenContinuedPublication SignerPollContinuedPublication SignerCloseContinuedPublication SignerExportOriginalFullPlan SignerOpenCommonContextRead SignerPollCommonContextRead SignerParkCommonContextCompletion SignerPeerMetadata SignerNativeEntry SignerEndpoint SignerProvider SignerDeadline SignerSingleController ObservedInputs ObservedRetainedPredecessor ObservedAssemble ObservedCandidateReview ObservedPlanExport ObservedPlanSign ObservedPlanRead ObservedPlanAuthenticate ObservedPlanWitness ObservedContinuation ObservedOwnerSplit ObservedReadPrepare ObservedReadHistory ObservedReadOpen ObservedReadPair ObservedReadFinish ObservedReadPark ObservedBarrier ObservedProviderDrain ConstructedPredecessor ConstructedDisclosure ConstructedWitnessOriginal ConstructedWitnessGrant ConstructedWitnessScope ConstructedPendingFile ConstructedPendingReview ConstructedSignerOpen ConstructedConsume ConstructedSignerPark ConstructedServerSeal ConstructedCheckpoint ConstructedSavedOriginal ConstructedInvariant ConstructedProviderDrain SignerOpenOriginalCompletion SignerPollOriginalCompletion ProvedConstructionDrain ProvedOriginalJob ProvedOriginalCorrelation ProvedHostPublic ProvedWitnessKey ProvedNamedOpen ProvedNamedPair ProvedNamedStatus ProvedNamedRecords ProvedNamedProfile ProvedNativePins ProvedCarrierPrepare ProvedCarrierExport ProvedCarrierRecover ProvedCarrierRetained ProvedCarrierInvariant SignerOpenOriginalNamed SignerPollOriginalNamed SignerRetainOriginalProfile SignerNamedEnrollmentExport SignerNamedInstalledMetadata SignerNamedVerifierArm SignerNamedVerifierStart SignerNamedVerifierPoll SignerNamedAssertionExport SignerNamedOriginalImport SignerNamedOriginalSubmit SignerNamedOriginalSign SignerNamedHostServing FullPaymentPredecessor FullEnrollmentExport FullEnrollmentInstall FullArtifactsInstall FullInstalledMetadata FullVerifierRequest FullAssertion FullOriginalImport FullAdmission FullSignatureReturn FullHistory FullReturnIntake FullMerge FullCurrentDispatch FullRecipientReceipt SingleAccountUnlock SingleRetainedRead SingleAcquireState SingleAttemptedSource SingleAttemptsRead SingleRetainedReopen SinglePreacquire SingleReference SingleAccountId SingleAudit SingleEndpointCreate SingleDirectoryOpen SingleIpcBind SingleEndpointPublish SingleWorkOpen SingleWorkPrepareIntent SingleWorkPrepareSignature SingleWorkPrepareExport SingleWorkPrepareReentry SingleWorkPrepareWitness SingleWorkPrepareAcquire SingleWorkPrepareActivate SingleWorkPreparePublication SingleWorkPrepareServe SingleWorkCommitPair SingleWorkCommitRetain SingleWorkCommitSignature SingleWorkCommitExport SingleWorkCommitReentry SingleWorkCommitWitness SingleWorkCommitAcquire SingleWorkCommitActivate SingleWorkCommitAdmission SingleWorkCommitPublication SingleWorkCommitServe SingleWorkRetryAcquire SingleWorkRetryActivate SingleWorkRetryAdmission SingleWorkOther SingleWorkAdoptOutput'.split())
OUTCOMES = frozenset('ExactPermission ExactLineage ExactBinding ExactStorage ExactRecoveryRequired ExactStateChanged ExactProfileChanged ExactBudget ExactRoster EngineAccessDenied EngineCandidateVerificationFailed EngineIdempotencyConflict EngineInvalidRequest EngineInvalidTransition EngineLiveAuthorizationExists EngineManualConstructionDenied EngineNotFound EngineRecoveryRequired EngineResourceExhausted EngineRetainedObservationUnavailable EngineRevisionConflict EngineStorageProtectionRequired EngineStorageUnavailable EngineUnclassified JobConsentDenied JobIdempotencyConflict JobInvalidRequest JobNotFound JobRecoveryRequired JobResourceExhausted JobStateConflict JobStorage JobUnsupportedSchema JobVerificationFailed ProtocolActionMapping ProtocolBuilderInput ProtocolBuilderOutput ProtocolContext ProtocolContribution ProtocolDisclosure ProtocolFee ProtocolFinalize ProtocolInput ProtocolManifest ProtocolOutput ProtocolPczt ProtocolUnclassified StoreAlreadyExists StoreBudgetExceeded StoreDatabase StoreEncoding StoreFile StoreIdempotencyConflict StoreInputReserved StoreInvalidInput StoreInvalidTransition StoreLiveAuthorizationExists StoreNotFound StorePoisoned StoreRecoveryRequired StoreResourceExhausted StoreRevisionConflict StoreStorageSecurity StoreUnsupportedSchema StoreWriterEpochMismatch BridgeBinding BridgeConflict BridgeMissing BridgeUncertain BridgeLimit BridgePermission BridgeRecoveryRequired BridgeCompleteOriginRecoveryUnavailable BridgeVerification BridgeSignerOriginUnavailable BridgeJournal BridgeAuthority BridgeWallet BridgeIpc AuthorityInputEmpty AuthorityInputWithinBound AuthorityInputOverBound AuthorityInvalidBinding AuthorityPermission AuthorityStaleHead AuthorityConflict AuthorityInactive AuthorityRecoveryRequired AuthorityExpired AuthorityPolicyDenied AuthorityBudgetExceeded AuthorityInputReserved AuthorityObligationReserved AuthorityLimit AuthorityStorage AuthorityCorruptHistory AuthorityPermanentStopUnavailable AuthorityOfflineHistoryUnsupported AuthorityConstructionHistoryUnsupported AuthorityUnsupportedVersion AuthorityAuthentication AuthorityUncertain AuthorityResolutionUnavailable AuthoritySessionRequired AuthoritySessionPending OriginPermanentStopUnavailable OriginRetirementEvidenceUnavailable OriginSignerOriginUnavailable OriginPeerLifetimeUnavailable OriginAuthentication OriginBinding OriginConflict OriginPermission OriginInvalidData OriginLocked OriginCrypto OriginIpc OriginLimit OriginIoTimedOut OriginIoWouldBlock OriginIoUnexpectedEof OriginIoBrokenPipe OriginIoConnectionReset OriginIoConnectionAborted OriginIoNotConnected OriginIoInterrupted OriginIoPermissionDenied OriginIoOther ImportFreshOwnerRequired ImportBinding ImportIncomplete ImportStorage SyncAccessDenied SyncInvalidRequest SyncInterrupted SyncReconciliationRequired SyncInvalidResponse SyncResourceLimit SyncNoCurrentObservation WalletStorage WalletAccountScope WalletAccountMismatch WalletIncompleteSync WalletUnsupportedProfile WalletChainMismatch WalletInsufficientFunds WalletInvalidRequest WalletMissingWitness WalletInvalidNote WalletScan WalletTransport ChainInvalidConfiguration ChainWrongNetwork ChainUnsupportedProxyConfiguration ChainWrongBranch ChainStaleChain ChainContradictoryChain ChainTimeout ChainTransportUnavailable ChainObservationInterrupted ChainMissingAncestryEvidence ChainNotObserved ChainResourceLimit ChainMalformedEvidence ChainUnsupportedCapability ChainBackendFailure ChainClockUnavailable ChainIdempotencyConflict ChainJournalFailure ChainSubmissionNotAuthorized ChainSubmissionExpiryMargin ChainObligationConflict ChainSubmissionOutcomeUnrecorded ChainSubmissionRetentionUncertain RecoveryAccessDenied RecoveryUnsupportedAccountComponents RecoveryIncompleteScan RecoveryKnownFundsRemain RecoveryAdditionalEvidenceRequired Begin Complete HostPlatform HostTerminal HostPermission HostLocked HostInvalid HostAuthentication HostStorage HostQuarantined HostUnsupported HostReceipt HostRecoverySemantic HostRecoveryBackupUnsupported HostRecoveryFinancialUnsupported HostCompleteOriginRecoveryUnavailable HostHistoricalExportIncomplete HostGenerationArchiveIncomplete SignerUnavailable SignerPeerLifetimeUnavailable SignerIo SignerAuthentication SignerInvalidData SignerCrypto SignerLocked SignerBackupRequired SignerRecoveryRequired SignerAlreadyOpen SignerReviewMismatch SignerVerification SignerUncertain SignerConsentJournal SignerStore WorkerFailure'.split())
IO_KINDS = frozenset('NotFound PermissionDenied AlreadyExists InvalidInput InvalidData AddrInUse AddrNotAvailable WouldBlock TimedOut Interrupted Unsupported Other'.split())
DURABLE_ENTRY_BOUNDARIES = frozenset('DurableEntryNativeOwnerCheck DurableEntryVaultOpen DurableEntryRetainedEnrollment DurableEntryOriginalCommit DurableEntryJournalOpen DurableEntrySourceCheck DurableEntryRuntimeActivation DurableEntryWorkerResult DurableEntryEndpointCreate DurableEntryEndpointBind DurableEntryEndpointPublish DurableEntryPostEndpointSourceCheck DurableEntryFixturePreflight DurableEntryFixturePostActivation'.split())
DURABLE_HOST_BOUNDARIES = frozenset('DurableHostOpen DurableHostPairStatus DurableHostPairObserved DurableHostAccept DurableHostInitialDisclosure DurableHostInitialObserved DurableHostRecipient DurableHostCaptureSetup DurableHostCapture DurableHostCaptureObserved DurableHostCaptureCommitted DurableHostIntake DurableHostClose DurableHostObserve DurableHostCheckpoint DurableHostProof DurableHostFreeze DurableHostReload DurableHostRedisclosure DurableHostReviewReady DurableHostReviewExport DurableHostReviewImported DurableHostProviderStop'.split())
DURABLE_FINANCIAL_BOUNDARIES = frozenset('DurableHostWitnessSetup DurableHostWriterReconcile DurableHostViewingSetup DurableHostSign DurableHostSignRetry DurableHostResultHistory DurableHostResultRetrieve DurableHostResultRelay DurableHostSignatureIntake DurableHostSignatureStatus DurableHostResultServiceStop DurableHostSignatureUnion DurableHostTransactionCheckpoint'.split())
SIGNER_ADMISSION_BOUNDARIES = frozenset('SignerAdmissionFixtureState SignerAdmissionSource SignerAdmissionHistory SignerAdmissionRetainedIntent SignerAdmissionTerms SignerAdmissionRequestBuilder SignerAdmissionExactRequest SignerAdmissionLiveInterval SignerAdmissionLocalIntent SignerAdmissionIntentDisplay SignerAdmissionReviewCustody SignerAdmissionReviewDisplay SignerAdmissionNativeStage SignerAdmissionWorkerCompletion'.split())
SIGNER_HISTORY_BOUNDARIES = frozenset('SignerAdmissionHistoryCallerDeadline SignerAdmissionHistoryExchangeDeadline SignerAdmissionHistorySourceCallback SignerAdmissionHistorySnapshotConnect SignerAdmissionHistorySnapshotHandshake SignerAdmissionHistorySnapshotPeerBinding SignerAdmissionHistorySnapshotRequestBuild SignerAdmissionHistorySnapshotRequestWrite SignerAdmissionHistorySnapshotResponseRead SignerAdmissionHistorySnapshotResponse SignerAdmissionHistorySnapshotValidation SignerAdmissionHistoryPageConnect SignerAdmissionHistoryPageHandshake SignerAdmissionHistoryPagePeerBinding SignerAdmissionHistoryPageRequestBuild SignerAdmissionHistoryPageRequestWrite SignerAdmissionHistoryPageResponseRead SignerAdmissionHistoryPageResponse SignerAdmissionHistoryPageValidation SignerAdmissionHistoryEventReplay SignerAdmissionHistoryFinalValidation SignerAdmissionHistoryBounds SignerAdmissionHistoryIoTimeout SignerAdmissionHistoryIoClosed SignerAdmissionHistoryIoRefused SignerAdmissionHistoryIoOther SignerAdmissionHistoryCallbackError'.split())
SIGNER_DISPATCH_BOUNDARIES = frozenset(['SignerAdmissionCallRequestValidation', 'SignerAdmissionCallBinding', 'SignerAdmissionCallConnect', 'SignerAdmissionCallHandshake', 'SignerAdmissionCallPeerBinding', 'SignerAdmissionCallRequestBuild', 'SignerAdmissionCallRequestWrite', 'SignerAdmissionCallResponseRead', 'SignerAdmissionCallResponse', 'SignerAdmissionCallSnapshotValidation', 'SignerAdmissionCallCommittedHeadValidation', 'SignerAdmissionCallFinalValidation', 'SignerAdmissionDispatchFixtureState', 'SignerAdmissionDispatchReviewCorrelation', 'SignerAdmissionDispatchNativeApproval', 'SignerAdmissionDispatchIntentRetention', 'SignerAdmissionDispatchSubmitCustody', 'SignerAdmissionDispatchSubmitIntent', 'SignerAdmissionDispatchSubmitInterval', 'SignerAdmissionDispatchSubmitWorkspace', 'SignerAdmissionDispatchAuthorityCall', 'SignerAdmissionDispatchWorkerCompletion', 'SignerAdmissionDispatchCommittedCorrelation', 'SignerAdmissionCallbackWorkspaceCurrent', 'SignerAdmissionCallbackCustody', 'SignerAdmissionCallbackRequestValidation', 'SignerAdmissionCallIoTimeout', 'SignerAdmissionCallIoClosed', 'SignerAdmissionCallIoRefused', 'SignerAdmissionCallIoOther', 'SignerAdmissionCallCallbackError', 'SignerAdmissionCallCallerDeadline', 'SignerAdmissionCallExchangeDeadline', 'SignerAdmissionCallSourceCallback', 'SignerAdmissionCallBounds'])
BOUNDARIES = BOUNDARIES | SIGNER_DISPATCH_BOUNDARIES | DURABLE_ENTRY_BOUNDARIES | DURABLE_HOST_BOUNDARIES | DURABLE_FINANCIAL_BOUNDARIES | SIGNER_ADMISSION_BOUNDARIES | SIGNER_HISTORY_BOUNDARIES
FALSE_FIELDS = {'public_network_settlement_verified','public_network_inclusion_verified','independent_consensus_verified','attended_native_acceptance_verified','clears_authorization_exposure','permits_replacement'}
INT_FIELDS = {'schema','consensus_branch_id','expiry_height','submission_attempt','recipient_decrypted_zatoshis','recipient_owned_note_count','fabricated_inclusion_height','fabricated_tip_height','required_confirmations'}
STRING_FIELDS = {'evidence_kind','transaction_id','transaction_bytes_sha256','network','submission_outcome'}

def distinct_object(pairs):
    result={}
    for key,value in pairs:
        if key in result: raise ValueError('duplicate public field')
        result[key]=value
    return result


def history_json(text, limit):
    if len(text.encode('utf8')) > limit: raise ValueError('oversized history measurement')
    def reject_constant(_):
        raise ValueError('nonfinite history measurement')
    try:
        return json.loads(text,object_pairs_hook=distinct_object,parse_constant=reject_constant)
    except (RecursionError,OverflowError):
        raise ValueError('invalid history measurement') from None


def history_bounded(value, limit):
    return type(value) is int and 0 <= value <= limit


def history_enum(value, values, nullable=False):
    return (nullable and value is None) or (type(value) is str and value in values)


def public_history_measurement(text):
    """First-error observations only. Exchange cost is contained in history cost."""
    row=history_json(text,4096)
    if type(row) is not dict or set(row)!=HISTORY_MEASUREMENT_FIELDS:
        raise ValueError('unexpected history measurement fields')
    if type(row['version']) is not int or row['version']!=1:
        raise ValueError('history measurement version')
    for field,values,nullable in (('phase',HISTORY_PHASES,True),
            ('check_site',HISTORY_CHECK_SITES,True),('checkpoint',HISTORY_CHECKPOINTS,False),
            ('selected_limit',HISTORY_SELECTED_LIMITS,True)):
        if not history_enum(row[field],values,nullable): raise ValueError('history measurement enum')
    ordinal=row['page_ordinal']
    if ordinal is not None and (not history_bounded(ordinal,4096) or ordinal==0):
        raise ValueError('history page ordinal')
    if (row['phase']=='Page') != (ordinal is not None): raise ValueError('history page context')
    for field in HISTORY_OPTIONAL_DURATIONS:
        if row[field] is not None and not history_bounded(row[field],HISTORY_DURATION_LIMIT_US):
            raise ValueError('history optional duration')
    for field in ('history_elapsed_us','pre_budget_callback_us'):
        if not history_bounded(row[field],HISTORY_DURATION_LIMIT_US):
            raise ValueError('history duration')
    if not history_bounded(row['pre_budget_callback_calls'],1): raise ValueError('history pre-budget count')
    if any(type(row[key]) is not bool for key in ('clamped','incomplete')):
        raise ValueError('history measurement flag')
    for field in ('history_cost','exchange_cost'):
        cost=row[field]
        if field=='exchange_cost' and cost is None: continue
        if type(cost) is not dict or set(cost)!=HISTORY_COST_COUNTS|HISTORY_COST_DURATIONS:
            raise ValueError('history cost fields')
        if any(not history_bounded(cost[key],HISTORY_COUNT_LIMIT) for key in HISTORY_COST_COUNTS):
            raise ValueError('history cost count')
        if any(not history_bounded(cost[key],HISTORY_DURATION_LIMIT_US) for key in HISTORY_COST_DURATIONS):
            raise ValueError('history cost duration')
    return row


def public_history_server_measurement(text):
    """Independent server observation, never readiness or authority evidence."""
    row=history_json(text,512)
    if type(row) is not dict or set(row)!=HISTORY_SERVER_MEASUREMENT_FIELDS:
        raise ValueError('unexpected history server measurement fields')
    if type(row['version']) is not int or row['version']!=1:
        raise ValueError('history server measurement version')
    if not history_enum(row['point'],HISTORY_SERVER_POINTS): raise ValueError('history server point')
    if row['age_us'] is not None and not history_bounded(row['age_us'],HISTORY_DURATION_LIMIT_US):
        raise ValueError('history server age')
    if not history_bounded(row['remaining_us'],HISTORY_DURATION_LIMIT_US):
        raise ValueError('history server remaining')
    if any(type(row[key]) is not bool for key in ('stopped','clamped')):
        raise ValueError('history server flag')
    if row['finished'] is not None and type(row['finished']) is not bool:
        raise ValueError('history server finished')
    return row


class HistoryMeasurements:
    """At most one failure and two independent server observations per run."""
    def __init__(self):
        self.client=None
        self.client_invalid=False
        self.server={}
        self.server_invalid=False

    def record(self, kind, value):
        if kind=='history_measurement_invalid':
            self.client_invalid=True; self.client=None
        elif kind=='history_measurement':
            if self.client_invalid: return
            if self.client is not None:
                self.client_invalid=True; self.client=None
            else: self.client=value
        elif kind=='history_server_measurement_invalid':
            self.server_invalid=True; self.server.clear()
        elif kind=='history_server_measurement':
            if self.server_invalid: return
            if value['point'] in self.server:
                self.server_invalid=True; self.server.clear()
            else: self.server[value['point']]=value

    def emit(self):
        if self.client_invalid:
            print('CI_SYNTHETIC_HISTORY_MEASUREMENT invalid=true details_withheld=true',flush=True)
        elif self.client is not None:
            print(HISTORY_MEASUREMENT_PREFIX+json.dumps(self.client,separators=(',',':'),sort_keys=True)+']',flush=True)
        if self.server_invalid:
            print('CI_SYNTHETIC_HISTORY_SERVER_MEASUREMENT invalid=true details_withheld=true',flush=True)
        else:
            for point in HISTORY_SERVER_POINTS:
                if point in self.server:
                    print(HISTORY_SERVER_MEASUREMENT_PREFIX+json.dumps(self.server[point],separators=(',',':'),sort_keys=True)+']',flush=True)


def admission_object(value, fields):
    if type(value) is not dict or set(value)!=fields:
        raise ValueError('admission exact fields')
    return value


def admission_duration(value):
    return value is None or history_bounded(value,HISTORY_DURATION_LIMIT_US)


def admission_flags(row):
    if any(type(row[key]) is not bool for key in ('clamped','incomplete')):
        raise ValueError('admission observation flags')


def public_admission_measurement(text):
    row=admission_object(history_json(text,4096),ADMISSION_MEASUREMENT_FIELDS)
    if type(row['version']) is not int or row['version']!=1: raise ValueError('admission version')
    for field,values,nullable in (('phase',{'Admission'},True),('check_site',ADMISSION_CHECK_SITES,True),
            ('checkpoint',HISTORY_CHECKPOINTS,False),('selected_limit',HISTORY_SELECTED_LIMITS,True)):
        if not history_enum(row[field],values,nullable): raise ValueError('admission enum')
    if any(not admission_duration(row[field]) for field in HISTORY_OPTIONAL_DURATIONS):
        raise ValueError('admission optional duration')
    for field in ('operation_elapsed_us','pre_budget_callback_us'):
        if not history_bounded(row[field],HISTORY_DURATION_LIMIT_US): raise ValueError('admission duration')
    if not history_bounded(row['pre_budget_callback_calls'],1): raise ValueError('admission pre-budget calls')
    admission_flags(row)
    for field in ('operation_cost','exchange_cost'):
        cost=row[field]
        if field=='exchange_cost' and cost is None: continue
        admission_object(cost,HISTORY_COST_COUNTS|HISTORY_COST_DURATIONS)
        if any(not history_bounded(cost[key],HISTORY_COUNT_LIMIT) for key in HISTORY_COST_COUNTS):
            raise ValueError('admission cost count')
        if any(not history_bounded(cost[key],HISTORY_DURATION_LIMIT_US) for key in HISTORY_COST_DURATIONS):
            raise ValueError('admission cost duration')
    return row


def public_signer_admission(text):
    row=admission_object(history_json(text,4096),SIGNER_ADMISSION_FIELDS)
    if type(row['version']) is not int or row['version']!=1: raise ValueError('signer admission version')
    for field,values,nullable in (('stage',SIGNER_ADMISSION_STAGES,False),
            ('completion',SIGNER_ADMISSION_COMPLETIONS,False),('retention',SIGNER_ADMISSION_RETENTIONS,False),
            ('original_error',SIGNER_ADMISSION_ERRORS,True),('callback_stage',SIGNER_ADMISSION_CALLBACK_STAGES,True)):
        if not history_enum(row[field],values,nullable): raise ValueError('signer admission enum')
    measured=row['measurement']
    if measured is not None:
        admission_object(measured,SIGNER_ADMISSION_MEASUREMENT_FIELDS)
        admission_flags(measured)
        if any(not admission_duration(measured[field]) for field in SIGNER_ADMISSION_DURATIONS):
            raise ValueError('signer admission duration')
        if any(measured[field] is not None and not history_bounded(measured[field],HISTORY_COUNT_LIMIT)
               for field in SIGNER_ADMISSION_COUNTS):
            raise ValueError('signer admission count')
    return row


def public_witness_admission(text):
    row=admission_object(history_json(text,4096),WITNESS_ADMISSION_FIELDS)
    if type(row['version']) is not int or row['version']!=1: raise ValueError('witness admission version')
    for field,values,nullable in (('worker_result',WITNESS_ADMISSION_RESULTS,False),
            ('fixture_result',WITNESS_ADMISSION_RESULTS,False),('worker_error',ADMISSION_AUTHORITY_ERRORS,True),
            ('fixture_error',ADMISSION_AUTHORITY_ERRORS,True),('worker_stage',WITNESS_ADMISSION_STAGES,True),
            ('fixture_stage',WITNESS_ADMISSION_STAGES,True),('completion',WITNESS_ADMISSION_COMPLETIONS,False),
            ('commit',WITNESS_ADMISSION_COMMITS,False),('receipt_gate',WITNESS_ADMISSION_RECEIPT_GATES,False),
            ('final_correlation',WITNESS_ADMISSION_CORRELATIONS,False)):
        if not history_enum(row[field],values,nullable): raise ValueError('witness admission enum')
    for field in ('controlled_result','snapshot_recorded'):
        if row[field] is not None and type(row[field]) is not bool: raise ValueError('witness admission observation')
    admission_flags(row)
    for field in ('first_semantic','first_connection'):
        error=row[field]
        if error is None: continue
        admission_object(error,WITNESS_ADMISSION_ERROR_FIELDS)
        for key,values,nullable in (('stage',WITNESS_ADMISSION_STAGES,False),
                ('attribution',WITNESS_ADMISSION_ATTRIBUTIONS,False),('io_kind',ADMISSION_IO_KINDS,True),
                ('error',ADMISSION_AUTHORITY_ERRORS,False)):
            if not history_enum(error[key],values,nullable): raise ValueError('witness admission error enum')
    costs=admission_object(row['cost'],WITNESS_ADMISSION_SPANS)
    for cost in costs.values():
        admission_object(cost,{'calls','elapsed_us'})
        if not history_bounded(cost['calls'],HISTORY_COUNT_LIMIT) or not admission_duration(cost['elapsed_us']):
            raise ValueError('witness admission cost')
    return row


ADMISSION_PARSERS = (public_admission_measurement,public_signer_admission,public_witness_admission)


class AdmissionDiagnostics:
    """Three independent, first-record-only slots; invalidation is sticky."""
    def __init__(self):
        self.records=[None,None,None]
        self.invalid=[False,False,False]

    def record(self, kind, value):
        for slot,name in enumerate(ADMISSION_KINDS):
            if kind not in (name,name+'_invalid'): continue
            if self.invalid[slot]: return
            if kind==name+'_invalid' or self.records[slot] is not None:
                self.records[slot]=None; self.invalid[slot]=True
            else: self.records[slot]=value
            return

    def emit(self):
        for slot,record in enumerate(self.records):
            # Optional serialization/output errors never become operational failure.
            try:
                if self.invalid[slot]: print(ADMISSION_INVALID[slot],flush=True)
                elif record is not None:
                    print(ADMISSION_PREFIXES[slot]+json.dumps(record,separators=(',',':'),sort_keys=True)+']',flush=True)
            except (OSError,ValueError,TypeError,OverflowError,RecursionError):
                pass


def flow_object(value, fields):
    if type(value) is not dict or set(value)!=set(fields):
        raise ValueError('flow exact fields')
    return {key:value[key] for key in fields}


def flow_error(value):
    row=flow_object(value,FLOW_ERROR_FIELDS)
    if not history_enum(row['stage'],FLOW_STAGE): raise ValueError('flow error stage')
    domain=row['domain']; code=row['code']
    if type(domain) is not str or domain not in FLOW_DOMAIN_CODES:
        raise ValueError('flow error domain')
    if not history_enum(code,FLOW_DOMAIN_CODES[domain]): raise ValueError('flow error code')
    if not history_enum(row['nested_code'],FLOW_NESTED_CODES.get((domain,code),()),True):
        raise ValueError('flow immediate nested code')
    return row


def flow_completion(value):
    row=flow_object(value,FLOW_COMPLETION_FIELDS)
    for field,values,nullable in (('purpose',FLOW_JOB_PURPOSE,True),('result',FLOW_RESULT,False),
            ('receive',FLOW_RECEIVE,False),('presentation',FLOW_PRESENTATION,False)):
        if not history_enum(row[field],values,nullable): raise ValueError('flow completion enum')
    purpose,result,receive,presentation=(row[key] for key in FLOW_COMPLETION_FIELDS)
    if purpose is None and (result!='NotObserved' or presentation!='NotObserved' or receive not in ('NotObserved','Missing')):
        raise ValueError('flow no actual job')
    if receive=='Received' and (purpose is None or result not in ('ReturnedOk','ReturnedErr')):
        raise ValueError('flow received result')
    if receive in ('Pending','Disconnected') and (result!='NotObserved' or presentation!='NotObserved'):
        raise ValueError('flow unreceived result')
    if presentation=='Accepted' and (receive!='Received' or result!='ReturnedOk'):
        raise ValueError('flow accepted presentation')
    if presentation=='Suppressed' and receive not in ('Received','Invalidated'):
        raise ValueError('flow suppressed presentation')
    return row


def flow_cost(value):
    row=flow_object(value,FLOW_COST_FIELDS)
    for key in FLOW_COST_FIELDS:
        bound=HISTORY_COUNT_LIMIT if key in HISTORY_COST_COUNTS else HISTORY_DURATION_LIMIT_US
        if not history_bounded(row[key],bound): raise ValueError('flow cost bound')
    return row


def flow_measurement(value, purpose):
    row=flow_object(value,FLOW_MEASUREMENT_FIELDS)
    if not history_enum(row['phase'],{purpose},True): raise ValueError('flow phase purpose')
    for field,values,nullable in (('check_site',ADMISSION_CHECK_SITES,True),
            ('checkpoint',HISTORY_CHECKPOINTS,False),('selected_limit',HISTORY_SELECTED_LIMITS,True)):
        if not history_enum(row[field],values,nullable): raise ValueError('flow measurement enum')
    if any(not admission_duration(row[key]) for key in HISTORY_OPTIONAL_DURATIONS):
        raise ValueError('flow duration')
    for key in ('operation_elapsed_us','pre_budget_callback_us'):
        if not history_bounded(row[key],HISTORY_DURATION_LIMIT_US): raise ValueError('flow duration')
    if not history_bounded(row['pre_budget_callback_calls'],1): raise ValueError('flow pre-budget count')
    admission_flags(row)
    row['operation_cost']=flow_cost(row['operation_cost'])
    if row['exchange_cost'] is not None: row['exchange_cost']=flow_cost(row['exchange_cost'])
    if purpose=='Reserve' and (row['caller_remaining_at_budget_start_us'] is not None
            or row['caller_remaining_at_failure_us'] is not None or row['selected_limit'] not in (None,'Exchange')):
        raise ValueError('flow reserve has no caller bound')
    return row


def flow_lower(value):
    row=flow_object(value,FLOW_LOWER_FIELDS)
    for field,values,nullable in (('purpose',FLOW_TRANSPORT_PURPOSE,False),
            ('stage',FLOW_TRANSPORT_STAGE,False),('authority_code',FLOW_AUTHORITY_CODE,False),
            ('io_kind',ADMISSION_IO_KINDS,True),('callback_stage',FLOW_CALLBACK_STAGE,True)):
        if not history_enum(row[field],values,nullable): raise ValueError('flow lower enum')
    row['measurement']=flow_measurement(row['measurement'],row['purpose'])
    return row


def public_durable_flow(text):
    row=flow_object(history_json(text,4096),FLOW_FIELDS)
    if type(row['version']) is not int or row['version']!=1: raise ValueError('flow version')
    if not history_enum(row['operation'],FLOW_OPERATION): raise ValueError('flow operation')
    if row['fixture_result']!='ReturnedErr': raise ValueError('flow is failure-only')
    for key in ('first_error','terminal_error'):
        if row[key] is not None: row[key]=flow_error(row[key])
    row['completion']=flow_completion(row['completion'])
    calls=flow_object(row['call_outcomes'],FLOW_CALL_FIELDS)
    if any(not history_enum(calls[key],FLOW_CALL_OUTCOME) for key in FLOW_CALL_FIELDS):
        raise ValueError('flow call outcome')
    row['call_outcomes']=calls
    admission_flags(row)
    if row['lower_call_measurement'] is not None:
        lower=flow_lower(row['lower_call_measurement'])
        row['lower_call_measurement']=lower
        for key in ('clamped','incomplete'):
            if lower['measurement'][key] and not row[key]: raise ValueError('flow lost lower flag')
    return row


class DurableFlowDiagnostics:
    """One failure-only slot; malformed/duplicate/oversized evidence is sticky."""
    def __init__(self):
        self.value=None
        self.invalid=False

    def record(self, kind, value):
        if kind not in ('durable_flow','durable_flow_invalid') or self.invalid: return
        if kind=='durable_flow_invalid' or self.value is not None:
            self.value=None; self.invalid=True
        else: self.value=value

    def emit(self):
        try:
            if self.invalid: print(FLOW_INVALID,flush=True)
            elif self.value is not None:
                # Revalidate, then serialize fixed field order, never forward text.
                value=public_durable_flow(json.dumps(self.value,separators=(',',':')))
                print(FLOW_PREFIX+json.dumps(value,separators=(',',':')),flush=True)
        except (OSError,ValueError,TypeError,KeyError,OverflowError,RecursionError):
            pass


def public_timing(text):
    """Optional measurement, never success/authorization evidence or a clock."""
    if len(text.encode('utf8')) > 8192: raise ValueError('oversized timing')
    row=json.loads(text,object_pairs_hook=distinct_object)
    fields={'version','complete','invalid','host_dump_complete','signer_dump_complete',
            'inclusive_aggregates','landmarks','aggregates'}
    if type(row) is not dict or set(row)!=fields: raise ValueError('unexpected timing fields')
    if type(row['version']) is not int or row['version']!=1: raise ValueError('timing version')
    for field in ('complete','invalid','host_dump_complete','signer_dump_complete','inclusive_aggregates'):
        if type(row[field]) is not bool: raise ValueError('timing flag')
    if row['inclusive_aggregates'] is not True: raise ValueError('timing interpretation')
    def bounded(value, limit):
        return type(value) is int and 0 <= value <= limit
    landmarks=row['landmarks']; aggregates=row['aggregates']
    if type(landmarks) is not list or len(landmarks)>len(TIMING_LANDMARK_SLOTS): raise ValueError('timing slots')
    if type(aggregates) is not list or len(aggregates)>len(TIMING_AGGREGATE_PHASES): raise ValueError('timing aggregates')
    seen=set()
    for item in landmarks:
        if type(item) is not dict or set(item)!={'kind','phase','ordinal','start_ms','end_ms','errors'}:
            raise ValueError('timing landmark fields')
        if item['kind']!='landmark' or type(item['phase']) is not str or type(item['ordinal']) is not str:
            raise ValueError('timing landmark kind')
        slot=(item['phase'],item['ordinal'])
        if slot not in TIMING_LANDMARK_SLOTS or slot in seen: raise ValueError('timing landmark identity')
        seen.add(slot)
        start=item['start_ms']; end=item['end_ms']; errors=item['errors']
        if not bounded(errors,1): raise ValueError('timing landmark errors')
        if start is not None and not bounded(start,900000): raise ValueError('timing start')
        if end is not None and not bounded(end,900000): raise ValueError('timing end')
        if end is None:
            if errors!=0: raise ValueError('timing unfinished result')
        elif start is None or end<start: raise ValueError('timing order')
    seen=set()
    for item in aggregates:
        if type(item) is not dict or set(item)!={'kind','phase','started','completed','errors','total_ms','max_ms'}:
            raise ValueError('timing aggregate fields')
        if item['kind']!='aggregate' or type(item['phase']) is not str or item['phase'] not in TIMING_AGGREGATE_PHASES or item['phase'] in seen:
            raise ValueError('timing aggregate identity')
        seen.add(item['phase'])
        if any(not bounded(item[k],1000000) for k in ('started','completed','errors')):
            raise ValueError('timing count')
        if not item['errors']<=item['completed']<=item['started']: raise ValueError('timing count order')
        if any(not bounded(item[k],900000000) for k in ('total_ms','max_ms')): raise ValueError('timing millis')
        if item['max_ms']>item['total_ms'] or (item['completed']==0 and item['total_ms']!=0):
            raise ValueError('timing total')
    complete=(not row['invalid'] and row['host_dump_complete'] and row['signer_dump_complete']
              and len(landmarks)==len(TIMING_LANDMARK_SLOTS) and len(aggregates)==len(TIMING_AGGREGATE_PHASES))
    if row['complete'] and not complete: raise ValueError('timing completeness')
    return row

def public_outcome(text):
    if len(text.encode()) > 4096: raise ValueError('oversized public result')
    row=json.loads(text,object_pairs_hook=distinct_object)
    if not isinstance(row,dict) or set(row)!=FALSE_FIELDS|INT_FIELDS|STRING_FIELDS: raise ValueError('unexpected public fields')
    if any(row[k] is not False for k in FALSE_FIELDS): raise ValueError('stronger outcome claim')
    for key in INT_FIELDS:
        bits = 16 if key=='schema' else 64 if key=='recipient_decrypted_zatoshis' else 32
        if type(row[key]) is not int or not 0 < row[key] < 2**bits: raise ValueError('invalid public amount/count')
    if row['schema']!=1 or row['submission_attempt']!=1 or row['recipient_owned_note_count']!=1: raise ValueError('unexpected public version/attempt')
    if not 1 <= row['required_confirmations'] <= 32 or row['fabricated_tip_height']-row['fabricated_inclusion_height']+1 < row['required_confirmations']: raise ValueError('invalid fabricated confirmation')
    for key in ['transaction_id','transaction_bytes_sha256']:
        if type(row[key]) is not str or not re.fullmatch('[0-9a-f]{64}',row[key]): raise ValueError('invalid public digest')
    if row['evidence_kind']!='synthetic_full_payment_v1' or row['network']!='testnet' or row['submission_outcome']!='synthetic_acknowledged': raise ValueError('unexpected result kind')
    return row

def exact_listing(text, name):
    # Actual rustc 1.99 libtest output. A known optional trailing newline is the
    # only variation; zero/multiple tests and arbitrary extra output are refused.
    return text.rstrip('\n') == name + ': test\n\n1 test, 0 benchmarks'

def option_i32(value):
    return value=='None' or (value.startswith('Some(') and int(value[5:-1]) < 2**31)

def safe_failure(line):
    match=FAILURE.fullmatch(line)
    if not match or not option_i32(match[1]) or not option_i32(match[2]): return False
    if int(match[4]) > int(match[5]): return False
    if match[6] not in HARNESS_FAILURE_REASONS: return False
    summary=match[7]
    if summary=='none': return True
    entries=summary.split(',')
    if len(entries)>64: return False
    for entry in entries:
        parts=entry.split(':')
        if not parts or parts[0] not in BOUNDARIES: return False
        if len(parts)==2 and parts[1] in OUTCOMES: continue
        if len(parts)!=3 or not parts[1].startswith('IoKind=') or parts[1][7:] not in IO_KINDS or not parts[2].startswith('errno='): return False
        errno=parts[2][6:]
        if errno=='none': continue
        if not re.fullmatch(r'0|-?[1-9][0-9]{0,9}',errno) or not -(2**31)<=int(errno)<2**31: return False
    return True

def flow_candidate(raw, name=None):
    prefix=('test '+name+' ... ').encode('utf8') if name is not None else None
    if prefix and raw.startswith(prefix): raw=raw[len(prefix):]
    return raw.startswith(b'CI_SYNTHETIC_DURABLE_FLOW')


def public_line(raw, name):
    if len(raw)>8192:
        return ('durable_flow_invalid',None) if flow_candidate(raw,name) else None
    try:
        line=raw.decode('utf8','strict').rstrip('\r')
    except UnicodeError:
        prefix=('test '+name+' ... ').encode('utf8')
        candidate=raw[len(prefix):] if raw.startswith(prefix) else raw
        if flow_candidate(candidate): return ('durable_flow_invalid',None)
        if candidate.startswith(TIMING_PREFIX.encode('ascii')):
            return ('timing_invalid',None)
        for marker,kind in ((HISTORY_MEASUREMENT_PREFIX,'history_measurement'),
                            (HISTORY_SERVER_MEASUREMENT_PREFIX,'history_server_measurement'),*zip(ADMISSION_PREFIXES,ADMISSION_KINDS)):
            if candidate.startswith(marker.encode('ascii')): return (kind+'_invalid',None)
        raise
    # No search inside arbitrary panic/text lines. Only libtest's exact prefix
    # or an entire standalone closed marker line is eligible for projection.
    prefix='test '+name+' ... '
    if line.startswith(prefix): line=line[len(prefix):]
    if CORE.fullmatch(line): return ('core',line)
    cleanup=CLEANUP.fullmatch(line)
    if cleanup and option_i32(cleanup[5]) and option_i32(cleanup[6]): return ('cleanup',line)
    if safe_failure(line): return ('failure',line)
    if line==FLOW_INVALID: return ('durable_flow_invalid',None)
    if line.startswith('CI_SYNTHETIC_DURABLE_FLOW'):
        try:
            if not line.startswith(FLOW_PREFIX): raise ValueError('flow framing')
            return ('durable_flow',public_durable_flow(line[len(FLOW_PREFIX):]))
        except (ValueError,TypeError,KeyError,OverflowError,RecursionError):
            return ('durable_flow_invalid',None)
    for slot,marker in enumerate(ADMISSION_INVALID):
        if line==marker: return (ADMISSION_KINDS[slot]+'_invalid',None)
    for marker,kind,parser in zip(ADMISSION_PREFIXES,ADMISSION_KINDS,ADMISSION_PARSERS):
        if line.startswith(marker):
            try:
                if not line.endswith(']'): raise ValueError('admission framing')
                return (kind,parser(line[len(marker):-1]))
            except (ValueError,TypeError,KeyError,OverflowError,RecursionError):
                return (kind+'_invalid',None)
    if line=='CI_SYNTHETIC_HISTORY_MEASUREMENT invalid=true details_withheld=true':
        return ('history_measurement_invalid',None)
    if line=='CI_SYNTHETIC_HISTORY_SERVER_MEASUREMENT invalid=true details_withheld=true':
        return ('history_server_measurement_invalid',None)
    for marker,kind,parser in ((HISTORY_MEASUREMENT_PREFIX,'history_measurement',public_history_measurement),
            (HISTORY_SERVER_MEASUREMENT_PREFIX,'history_server_measurement',public_history_server_measurement)):
        if line.startswith(marker):
            try:
                if not line.endswith(']'): raise ValueError('history measurement framing')
                return (kind,parser(line[len(marker):-1]))
            except (ValueError,TypeError,KeyError,OverflowError,RecursionError):
                return (kind+'_invalid',None)
    if line.startswith(TIMING_PREFIX):
        try:
            if not line.endswith(']'): raise ValueError('timing framing')
            return ('timing',public_timing(line[len(TIMING_PREFIX):-1]))
        except (ValueError, TypeError, KeyError, OverflowError, RecursionError):
            # Optional diagnostics cannot replace the original scenario outcome.
            return ('timing_invalid',None)
    if line.startswith(MARKER): return ('outcome',public_outcome(line[len(MARKER):]))
    return None

class BoundedLines:
    """Oversized physical lines stay discarded until their actual newline."""
    def __init__(self, name=None):
        self.name=name
        self.pending=bytearray()
        self.discarding=False

    def feed(self, chunk):
        lines=[]
        while chunk:
            split=chunk.find(b'\n')
            part=chunk if split<0 else chunk[:split]
            if not self.discarding:
                if len(self.pending)+len(part)>8192:
                    # Preserve the raw cap. Only a fixed invalid notification,
                    # never the oversized line, reaches the optional Flow slot.
                    head=bytes(self.pending[:8192])+part[:8192-len(self.pending)]
                    if flow_candidate(head,self.name): lines.append(FLOW_INVALID.encode('ascii'))
                    self.pending.clear()
                    self.discarding=True
                else:
                    self.pending.extend(part)
            if split<0: break
            if not self.discarding:
                lines.append(bytes(self.pending))
            self.pending.clear()
            self.discarding=False
            chunk=chunk[split+1:]
        return lines

DURABLE_PROVIDER_METADATA_TEST = PREFIX + 'synthetic_born_provider_v1::durable_metadata_tests::durable_provider_metadata_satisfies_actual_material_decoder'

def run_pure(executable):
    assert resource.getrlimit(resource.RLIMIT_CORE)[0] == 0
    for name in PURE_TESTS + POLICY_ENVELOPE_TESTS + PROMPT_RENDERING_TESTS + LOWER_ERROR_TESTS + DENIAL_TESTS + ROLLING_TRANSCRIPT_TESTS + AUTHORITY_PROJECTION_TESTS + READ_WAVE_TESTS + HISTORY_MEASUREMENT_TESTS + HISTORY_TRANSCRIPT_TESTS + ADMISSION_PROJECTION_TESTS + ADMISSION_TRANSCRIPT_TESTS + ADMISSION_HOST_TESTS + FLOW_PROJECTION_TESTS + FLOW_TRANSCRIPT_TESTS + FLOW_HOST_TESTS + TIMING_HOST_TESTS + (DURABLE_PROVIDER_METADATA_TEST,):
        flags=['--exact',name,'--test-threads=1']
        listed=subprocess.run([executable,*flags,'--list'],capture_output=True,timeout=30,check=True)
        if not exact_listing(listed.stdout.decode(),name) or listed.stderr:
            raise ValueError('exact pure test not uniquely registered')
        # These 72 fixed source-reviewed cases use only modeled process state,
        # inert files, historical policy DTOs, fixed prompts, closed error kinds or
        # bounded private parsing state or data-only scanned-note mathematics. They create
        # no native/IPC/network/payment owners.
        result=subprocess.run([executable,*flags],stdout=subprocess.PIPE,stderr=subprocess.STDOUT,timeout=30)
        if result.returncode!=0 or len(result.stdout)>1024*1024:
            print('CI_SYNTHETIC_PURE failed_test='+name,flush=True)
            raise RuntimeError('exact pure test failed; raw output withheld')
    print('CI_SYNTHETIC_PURE passed=72 raw_output_discarded=true',flush=True)

def run_signer_validation(executable):
    assert resource.getrlimit(resource.RLIMIT_CORE)[0] == 0
    for name in SIGNER_VALIDATION_TESTS + SIGNER_BOOKKEEPING_TESTS + SIGNER_PRECONSTRUCTION_TESTS + SIGNER_BIRTH_LINK_TESTS + SIGNER_ENDPOINT_CHANNEL_TESTS + SIGNER_SNAPSHOT_STORAGE_TESTS + SIGNER_SHAPE_TAMPER_TESTS + SIGNER_REENTRY_COMPATIBILITY_TESTS + SIGNER_CALL_LOCAL_TESTS + SIGNER_AUDIT_STORAGE_TESTS + SIGNER_AUDIT_COMPATIBILITY_TESTS + SIGNER_NAMED_ORIGIN_SNAPSHOT_TESTS + SIGNER_LINEAGE_PREDICATE_TESTS + SIGNER_TIMING_TESTS + SIGNER_DURABLE_LABEL_TESTS + SIGNER_DURABLE_RECEIPT_TESTS:
        flags=['--exact',name,'--test-threads=1']
        try:
            listed=subprocess.run([executable,*flags,'--list'],capture_output=True,timeout=30,check=True)
            if not exact_listing(listed.stdout.decode(),name) or listed.stderr:
                raise ValueError('exact signer validation test not uniquely registered')
            # Four actual BIP39/ZIP32/encrypted-file cases, two inert nonce
            # bookkeeping cases, six authenticated historical replay cases and
            # four real bounded in-process endpoint channels with current-image
            # identity/private facade bookkeeping, two encrypted snapshot cases,
            # one pure shape-tamper case and three archival/storage compatibility
            # cases, two call-local validation cases, one encrypted saved-digest
            # case, two signed-history audit compatibility cases and three encrypted
            # named-origin snapshot cases, two inert lineage equality cases, and three
            # fixed timing-counter model cases, one actual label grammar case and five
            # encrypted current-receipt restriction cases. No socket,
            # native authority or payment owner. Raw
            # output stays private; this size check is post-capture, not a claim
            # of an incremental memory cap. Each fixed case has its own bound.
            result=subprocess.run([executable,*flags],stdout=subprocess.PIPE,stderr=subprocess.STDOUT,timeout=120)
            if result.returncode!=0 or len(result.stdout)>1024*1024:
                raise RuntimeError('exact signer validation regression failed')
        except Exception:
            print('CI_SYNTHETIC_SIGNER_VALIDATION failed_test='+name+' raw_output_withheld=true',flush=True)
            raise
    print('CI_SYNTHETIC_SIGNER_VALIDATION passed=41 crypto_file_cases=4 bookkeeping_cases=2 replay_cases=6 endpoint_channel_cases=4 snapshot_storage_cases=2 shape_tamper_cases=1 compatibility_cases=3 call_local_cases=2 audit_storage_cases=1 audit_compatibility_cases=2 named_origin_snapshot_cases=3 lineage_predicate_cases=2 timing_counter_cases=3 label_grammar_cases=1 current_receipt_cases=5 native_payment_verified=false raw_output_discarded=true',flush=True)

def run_signer_durable_endpoint(executable):
    """One CI-only LocalIpc case, with no child processes or public raw output."""
    try:
        if (os.environ.get('GITHUB_ACTIONS')!='true' or
                os.environ.get('RUNNER_OS')!='Linux' or sys.platform!='linux'):
            raise ValueError('endpoint regression is isolated Linux CI only')
        if resource.getrlimit(resource.RLIMIT_CORE)[0]!=0:
            raise ValueError('endpoint regression requires own zero core limit')
        name=SIGNER_DURABLE_ENDPOINT_TEST
        flags=['--exact',name,'--test-threads=1']
        for listing,seconds,limit in ((True,30,8192),(False,120,1024*1024)):
            # Both phases stream instead of capture_output/communicate. Only
            # the bounded listing is retained; runtime bytes are discarded.
            deadline=time.monotonic()+seconds
            process=subprocess.Popen(
                [executable,*flags,('--list' if listing else '--nocapture')],
                stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,
                stderr=(subprocess.PIPE if listing else subprocess.STDOUT))
            status=None
            try:
                streams=[process.stdout]+([process.stderr] if listing else [])
                listed=bytearray(); total=0; stderr_seen=False
                while streams:
                    remaining=deadline-time.monotonic()
                    if remaining<=0: raise TimeoutError('endpoint phase deadline')
                    ready,_,_=select.select(streams,[],[],min(0.2,remaining))
                    for stream in ready:
                        chunk=os.read(stream.fileno(),min(65536,limit-total+1))
                        if not chunk:
                            streams.remove(stream)
                            continue
                        total+=len(chunk)
                        if total>limit: raise ValueError('endpoint output bound exceeded')
                        if listing:
                            if stream is process.stdout: listed.extend(chunk)
                            else: stderr_seen=True
                # EOF alone is not completion. Keep exit observation inside
                # this phase's original deadline, not an extra runtime grant.
                remaining=deadline-time.monotonic()
                if remaining<=0: raise TimeoutError('endpoint exit observation deadline')
                status=process.wait(timeout=remaining)
                if status!=0: raise RuntimeError('endpoint phase exited unsuccessfully')
                if listing and (stderr_seen or not exact_listing(listed.decode('utf8','strict'),name)):
                    raise ValueError('endpoint test not uniquely registered')
            finally:
                if status is None:
                    # Only this direct, thread-only test process is owned. A
                    # forced stop never proves endpoint/runtime-root cleanup.
                    try: process.kill()
                    except Exception: pass
                    try: process.wait(timeout=5)
                    except Exception: pass
                if process.stdout is not None: process.stdout.close()
                if process.stderr is not None: process.stderr.close()
    except Exception:
        print('CI_SYNTHETIC_SIGNER_DURABLE_ENDPOINT passed=false cleanup_unverified=true raw_output_withheld=true',flush=True)
        raise RuntimeError('CI-only endpoint regression failed; details withheld') from None
    # Actual test assertions cover both bind/drain cycles. The outer shell must
    # still verify its isolated runtime container is empty before job success.
    print('CI_SYNTHETIC_SIGNER_DURABLE_ENDPOINT passed=1 endpoint_cycles=2 native_payment_verified=false runtime_root_cleanup_pending=true raw_output_discarded=true',flush=True)

def run_authority_rendering(executable):
    assert resource.getrlimit(resource.RLIMIT_CORE)[0] == 0
    for name in AUTHORITY_RENDERER_TESTS:
        flags=['--exact',name,'--test-threads=1']
        try:
            listed=subprocess.run([executable,*flags,'--list'],capture_output=True,timeout=30,check=True)
            if not exact_listing(listed.stdout.decode(),name) or listed.stderr:
                raise ValueError('exact authority renderer test not uniquely registered')
            # Actual egui Context/Window rendering with inert fields only. No
            # TLS, files, process, native authority or IPC owner is created.
            # Output is withheld; the size check is post-capture, not a claim
            # of incremental memory bounds. The fixed cases run separately.
            result=subprocess.run([executable,*flags],stdout=subprocess.PIPE,stderr=subprocess.STDOUT,timeout=30)
            if result.returncode!=0 or len(result.stdout)>1024*1024:
                raise RuntimeError('exact authority renderer regression failed')
        except Exception:
            print('CI_SYNTHETIC_AUTHORITY_RENDERER failed_test='+name+' raw_output_withheld=true',flush=True)
            raise
    print('CI_SYNTHETIC_AUTHORITY_RENDERER passed=6 native_payment_verified=false attended_gui_verified=false raw_output_discarded=true',flush=True)

def run_authority_validation(executable):
    assert resource.getrlimit(resource.RLIMIT_CORE)[0] == 0
    for name in AUTHORITY_VALIDATION_TESTS:
        flags=['--exact',name,'--test-threads=1']
        try:
            listed=subprocess.run([executable,*flags,'--list'],capture_output=True,timeout=30,check=True)
            if not exact_listing(listed.stdout.decode(),name) or listed.stderr:
                raise ValueError('exact authority validation test not uniquely registered')
            # Three immutable validation/equivalence cases replay an existing
            # public signed fixture. No key, process, wallet, native/IPC owner or
            # payment is created. These are not renderer or attended GUI cases.
            # Raw output stays private. The size bound is post-capture only.
            result=subprocess.run([executable,*flags],stdout=subprocess.PIPE,stderr=subprocess.STDOUT,timeout=120)
            if result.returncode!=0 or len(result.stdout)>1024*1024:
                raise RuntimeError('exact authority validation regression failed')
        except Exception:
            print('CI_SYNTHETIC_AUTHORITY_VALIDATION failed_test='+name+' raw_output_withheld=true',flush=True)
            raise
    print('CI_SYNTHETIC_AUTHORITY_VALIDATION passed=3 immutable_replay_cases=3 native_payment_verified=false raw_output_discarded=true',flush=True)

def run_storage_bootstrap(executable):
    assert resource.getrlimit(resource.RLIMIT_CORE)[0] == 0
    flags=['--exact',STORAGE_BOOTSTRAP_TEST,'--test-threads=1']
    listed=subprocess.run([executable,*flags,'--list'],capture_output=True,timeout=30,check=True)
    if not exact_listing(listed.stdout.decode(),STORAGE_BOOTSTRAP_TEST) or listed.stderr:
        raise ValueError('exact encrypted bootstrap test not uniquely registered')
    # Real maintained encrypted empty archive8 -> layered9 -> later pending
    # provenance regression. No terminal/IPC/native authority/payment owner.
    # Keep this result separate from the 18 pure/model/filesystem test cases.
    result=subprocess.run([executable,*flags],stdout=subprocess.PIPE,stderr=subprocess.STDOUT,timeout=300)
    if result.returncode!=0 or len(result.stdout)>1024*1024:
        print('CI_SYNTHETIC_ENCRYPTED_BOOTSTRAP passed=false raw_output_withheld=true',flush=True)
        raise RuntimeError('exact encrypted bootstrap regression failed')
    print('CI_SYNTHETIC_ENCRYPTED_BOOTSTRAP passed=true native_payment_verified=false',flush=True)

def phase_selection(phase):
    name, seconds = TESTS[phase]
    flags = ['--exact', name, '--test-threads=1'] + (['--ignored'] if phase in ('full','durable-owner-reopen','durable-fixed-signing') else [])
    return name, seconds, flags

def run(executable, phase):
    assert resource.getrlimit(resource.RLIMIT_CORE)[0] == 0
    name, seconds, flags = phase_selection(phase)
    listed=subprocess.run([executable,*flags,'--list'],capture_output=True,timeout=30,check=True)
    assert exact_listing(listed.stdout.decode(),name) and not listed.stderr, 'Exact test not uniquely registered'
    started=time.monotonic(); process=subprocess.Popen([executable,*flags,'--nocapture'],stdout=subprocess.PIPE,stderr=subprocess.STDOUT)
    assert process.stdout is not None
    framing=BoundedLines(name); total=0; cleanup=False; cleanup_observed=False; cleanups=0; cores=0; failures=0; outcome=None; status=None; timing=None; timing_count=0; timing_invalid=False
    history_measurements=HistoryMeasurements()
    admission_diagnostics=AdmissionDiagnostics()
    durable_flow=DurableFlowDiagnostics()
    try:
        eof=False
        while not eof:
            if time.monotonic()-started > seconds: raise TimeoutError('outer runtime deadline')
            ready,_,_=select.select([process.stdout],[],[],0.2)
            if not ready: continue
            chunk=os.read(process.stdout.fileno(),65536)
            if not chunk: eof=True; continue
            total+=len(chunk)
            if total > 16*1024*1024: raise ValueError('bounded runtime output exceeded')
            for raw in framing.feed(chunk):
                try: projected=public_line(raw,name)
                except UnicodeError: projected=None
                if projected is None: continue
                kind,value=projected
                if kind=='core':
                    cores+=1
                    if cores>1: raise ValueError('duplicate core policy')
                    print(value,flush=True)
                elif kind=='cleanup':
                    cleanups+=1
                    if cleanups>1: raise ValueError('duplicate cleanup result')
                    fields=CLEANUP.fullmatch(value)
                    cleanup_observed=fields[1]!='Unverified' and fields[2]=='OriginalGroupAbsentObserved' and fields[3]=='Reaped' and fields[4]=='ClosedAndAbsenceVerified'
                    cleanup=fields[1]!='Unverified' and fields[2]=='OriginalGroupAbsentObserved' and fields[3]=='Reaped' and fields[4]=='ClosedAndAbsenceVerified' and fields[5]=='Some(0)' and fields[6]=='None' and fields[7]=='false'
                    print(value,flush=True)
                elif kind=='failure':
                    failures+=1
                    if failures>1: raise ValueError('duplicate failure result')
                    print(value,flush=True)
                elif kind in ('timing','timing_invalid'):
                    timing_count+=1
                    if timing_count>1 or phase!='full' or kind=='timing_invalid': timing_invalid=True
                    else: timing=value
                elif kind in ('history_measurement','history_measurement_invalid',
                              'history_server_measurement','history_server_measurement_invalid'):
                    if phase=='durable-fixed-signing': history_measurements.record(kind,value)
                elif kind in ADMISSION_KINDS or kind in tuple(name+'_invalid' for name in ADMISSION_KINDS):
                    if phase=='durable-fixed-signing': admission_diagnostics.record(kind,value)
                elif kind in ('durable_flow','durable_flow_invalid'):
                    if phase=='durable-fixed-signing': durable_flow.record(kind,value)
                elif kind=='outcome':
                    if phase!='full' or outcome is not None: raise ValueError('unexpected duplicate public outcome')
                    outcome=value
        status=process.wait(timeout=10)
    finally:
        if status is None:
            # This handles only our direct test parent. No claim about its
            # separate-session descendants; retain runtime root for job disposal.
            process.kill()
            try: process.wait(timeout=5)
            except subprocess.TimeoutExpired: pass
            print('CI_SYNTHETIC_RESULT cleanup_unverified=true outcome_unverified=true',flush=True)
    # Measurement is optional and emitted only after the independently observed
    # process/root cleanup. Failure exit statuses still retain bounded timing;
    # malformed/missing/duplicate timing never changes the original result gate.
    if phase=='durable-fixed-signing' and cleanup_observed:
        history_measurements.emit()
        admission_diagnostics.emit()
        durable_flow.emit()
    if phase=='full' and cleanup_observed:
        if timing_invalid:
            print('CI_SYNTHETIC_TIMING invalid=true details_withheld=true',flush=True)
        elif timing is None:
            print('CI_SYNTHETIC_TIMING missing=true details_withheld=true',flush=True)
        else:
            print(TIMING_PREFIX+json.dumps(timing,separators=(',',':'),sort_keys=True)+']',flush=True)
    if status!=0 or not cleanup or cores!=1 or failures or (phase=='full' and outcome is None):
        raise RuntimeError('synthetic phase failed or required cleanup/outcome evidence missing')
    if outcome is not None:
        text=MARKER+json.dumps(outcome,separators=(',',':'),sort_keys=True)
        print(text,flush=True)
        summary=os.environ.get('GITHUB_STEP_SUMMARY')
        if summary:
            with open(summary,'a',encoding='utf8') as f:
                f.write('Synthetic-only payment receipt, not public-chain settlement:\n'+text+'\n')
    print(f'CI_SYNTHETIC_RESULT phase={phase} passed=true cleanup_verified=true',flush=True)

if __name__=='__main__':
    try:
        assert len(sys.argv)==3 and sys.argv[2] in {*TESTS,'pure','storage-bootstrap','signer-validation','signer-durable-endpoint','authority-rendering'}
        exe=pathlib.Path(sys.argv[1]).resolve(strict=True)
        assert exe.is_file() and exe.is_relative_to(pathlib.Path(os.environ['CARGO_TARGET_DIR']).resolve(strict=True))
        if sys.argv[2]=='pure': run_pure(str(exe))
        elif sys.argv[2]=='signer-validation': run_signer_validation(str(exe))
        elif sys.argv[2]=='signer-durable-endpoint': run_signer_durable_endpoint(str(exe))
        elif sys.argv[2]=='authority-rendering':
            run_authority_rendering(str(exe))
            run_authority_validation(str(exe))
        elif sys.argv[2]=='storage-bootstrap': run_storage_bootstrap(str(exe))
        else: run(str(exe),sys.argv[2])
    except Exception:
        # Never serialize arbitrary exception text or raw test output.
        print('CI_SYNTHETIC_RESULT passed=false details_withheld=true',flush=True)
        sys.exit(1)
