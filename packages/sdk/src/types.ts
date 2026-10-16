/** Wire values are canonical decimal integer strings; never use floating-point money. */
export type Zatoshis = string & { readonly __zatoshis: unique symbol };
export type Id = string;
export type CapabilityStatus = 'supported' | 'experimental' | 'unavailable';
export interface Capability { status: CapabilityStatus; reason_code?: string | null; reason?: string; evidence_reference?: string | null; operations?: string[]; api_access?: 'local_http' | 'local_http_request_only' | 'embedded_only' | 'unavailable'; }
export interface CapabilitySet {
  api_version: string; engine_version: string;
  features: Record<string, Capability>;
  profiles: Record<string, unknown>[] | Record<string, unknown>;
  adapters: Record<string, unknown>[] | Record<string, unknown>;
  limits: Record<string, number | string>;
  runtime: Record<string, unknown>;
}
export interface Session { schema_version: 1; client_id: string; permissions: string[]; agreement_ids: string[]; all_agreements: boolean; include_owned_agreements?: boolean; agreement_scope?: "selected" | "owned_and_selected" | "all"; session_token: string; csrf_token: string; expires_in_seconds: number; }
export interface Recipient { recipient_id: Id; address: string; amount: Zatoshis; memo: string | null; instruction_provenance: string; }
export interface PrivacyProfile { mode: 'local_only' | 'declared_operator'; proving_operator: string | null; dedicated_accounts_required: boolean; }
export interface AgreementDraft {
  schema_version: 1; agreement_id: Id; obligation_id: Id; revision: number;
  purpose: string; organizer_identity: string; network_profile_id: string;
  recipients: Recipient[]; funding_policy: { kind: 'exact'; target: Zatoshis };
  fee_policy: { kind: 'pro_rata' } | { kind: 'sponsor'; participant_id: Id; amount: Zatoshis };
  privacy_profile: PrivacyProfile; coordination_deadline: string | null;
  confirmation_policy: { required_confirmations: number };
  extensions: { name: string; required: boolean; schema_version: number; value: unknown }[];
}
export type AgreementProgress = 'draft' | 'gathering_intent' | 'preparing_proposal' | 'awaiting_authorization' | 'ready_for_submission' | 'submission_attempted' | 'observing_settlement' | 'declined' | 'requires_revision' | 'validation_failed' | 'obsolete' | 'cancel_requested' | 'cancellation_requested' | 'closed';
export type AuthorizationState = 'unknown' | 'not_authorized' | 'authorized_locally' | 'released' | 'outstanding_uncertain' | 'expired_observed' | 'conflicted_observed' | 'consumed';
export type ChainStatus = 'unknown' | 'not_submitted' | 'submission_unknown' | 'backend_rejected' | 'pending_observed' | 'included' | 'confirmation_policy_met' | 'reorganized' | 'expired_observed' | 'conflicted_observed';
export interface ParticipationIntent {
  intent_id: Id; agreement_id: Id; participant_id: Id;
  desired_contribution: Zatoshis; maximum_net_debit: Zatoshis; fee_cap: Zatoshis;
  conditions: string[]; valid_until: string | null;
  status: 'active' | 'withdrawn' | 'selected' | 'waitlisted' | 'expired' | 'declined';
}
/** Service-owned eligibility for append-only revisions of unshared, pre-participation terms. */
export interface AgreementTermsEditability { allowed: boolean; reason: string; }
export interface AgreementView {
  terms_history?: AgreementDraft[]; terms_editability?: AgreementTermsEditability;
  agreement: AgreementDraft; revision: number; cancellation_requested: boolean; progress: AgreementProgress; authorization_exposure: AuthorizationState;
  chain_observation: ChainStatus; roster_selected?: boolean; intents: ParticipationIntent[]; created_at?: string; updated_at?: string;
  proposals?: ProposalPreview[]; verification_reports?: TermsReviewReport[]; candidates?: CandidateView[]; observations?: ChainObservation[]; events?: WholepactEvent[];
}
export interface ChainObservation {
  observation_id: Id; source_id: Id; observed_at: string; synchronized: boolean;
  status: ChainStatus; tip_height: number; confirmations: number;
  inclusion_height?: number | null; evidence_ref?: string | null;
}
export interface ProposalRevision {
  proposal_id: Id; agreement_id: Id; obligation_id: Id; revision: number;
  previous_proposal_id: Id | null; manifest: Record<string, unknown>; manifest_digest: string;
  artifact_ref: string | null; artifact_digest: string | null; effects_commitment: string | null;
  profile_id: string; chain_context: Record<string, unknown>; expiry_height: number; created_at: string;
}
export interface VerificationReport {
  report_id: Id; proposal_id: Id; manifest_digest: string; artifact_digest: string;
  effects_commitment: string; verifier_profile_id: string; participant_id: Id;
  checked_at: string; status: 'verified' | 'rejected' | 'incomplete' | 'unsupported';
  checks: { code: string; result: string; evidence_provenance?: string; trust_source?: string }[];
  review_summary: { maximum_net_debit: Zatoshis; contribution: Zatoshis; fee_share: Zatoshis; recipients: Recipient[]; change_outputs: { address: string; amount: Zatoshis; ownership_evidence: string }[]; match_assurance: string; expiry_height: number; network: string; disclosure_recipients: { recipient: string; information: string[]; retention: string }[] };
  blocking_errors: ApiErrorBody[]; valid_until: string;
}
export interface AuthorizationRecord {
  authorization_id: Id; obligation_id: Id; proposal_id: Id; participant_id: Id; account_id: Id;
  writer_epoch: number; manifest_digest: string; effects_commitment: string; maximum_net_debit: Zatoshis;
  state: AuthorizationState; signer_operation_id: Id; created_at: string;
  release_operation_id: Id | null; resolution_evidence: unknown;
}
export interface AccountRecord { account_id: Id; label: string; signer_profile_id: string; network_profile_id: string; status: string; balance?: Zatoshis | null; recovery_status: string; }
export interface SettlementRecord { record_id: Id; agreement_id: Id; proposal_id: Id; transaction_id: string; observed_at: string; confirmations: number; status: ChainStatus; }
export interface ApiErrorBody { code: string; message: string; retryable: boolean; operation_id?: Id | null; details?: unknown; safe_actions?: string[]; }
export interface Operation<T = unknown> { operation_id: Id; kind: string; resource_id: Id | null; status: 'accepted' | 'running' | 'awaiting_review' | 'uncertain' | 'succeeded' | 'failed' | 'cancel_requested'; progress?: number | null; result?: T; error?: ApiErrorBody | null; created_at?: string; updated_at?: string; }
export interface WholepactEvent { event_id: Id; sequence: number; occurred_at: string; aggregate_type: string; aggregate_id: Id; aggregate_revision: number; kind: string; payload: unknown; operation_id: Id | null; }
export interface MutationOptions { idempotencyKey: string; expectedRevision?: number; signal?: AbortSignal; }

/** Current development endpoint: immutable terms only, never a signable transaction. */
export interface ProposalPreview { proposal_id: Id; agreement_id: Id; obligation_id: Id; revision: number; previous_proposal_id: Id | null; manifest: Record<string, unknown>; manifest_digest: string; artifact_digest: null; effects_commitment: null; status: 'terms_only_not_signable'; created_at: string; }
export interface TermsReviewReport { report_id: Id; proposal_id: Id; manifest_digest: string; artifact_digest: null; effects_commitment: null; status: 'unsupported'; checked_at: string; checks: Record<string, unknown>[]; blocking_errors: ApiErrorBody[]; review_summary: { signable: false; scope: 'nonbinding_terms_only'; message: string }; }

/** Immutable unsigned candidate claims. This DTO is never privileged evidence. */
export interface ParticipantAllocation { participant_id: Id; account_id: Id; contribution: Zatoshis; fee_share: Zatoshis; fee_cap: Zatoshis; maximum_net_debit: Zatoshis; charges: { charge_id: Id; address: string; amount: Zatoshis; purpose: string }[]; }
export interface ClaimedInput { input_id: Id; participant_id: Id; account_id: Id; amount: Zatoshis; ownership_evidence_ref: string | null; }
export type OutputAllocation = { kind: 'recipient'; recipient_id: Id } | { kind: 'return'; participant_id: Id; account_id: Id; ownership_evidence_ref: string | null } | { kind: 'charge'; participant_id: Id; charge_id: Id };
export interface ClaimedOutput { output_id: Id; address: string; amount: Zatoshis; allocation: OutputAllocation; }
export interface CandidateManifest { agreement: AgreementDraft; participants: ParticipantAllocation[]; inputs: ClaimedInput[]; outputs: ClaimedOutput[]; transaction_fee: Zatoshis; expiry_height: number; }
export interface CandidateRequest { manifest: CandidateManifest; previous_candidate_id: Id | null; }
export interface CandidateReview {
  report_id: Id; candidate_id: Id; manifest_digest: string; checked_at: string;
  status: 'claims_checked_only' | 'economic_terms_verified_only'; scope: 'syntax_and_claimed_accounting' | 'local_cryptographic_economic_computation';
  artifact_digest: string | null; effects_commitment: string | null; review_binding: string | null;
  exact_fee_zatoshis: Zatoshis; participant_net_debits_zatoshis: Record<Id, Zatoshis>; economic_terms_verified: boolean;
  account_associations_authenticated: false; disclosure_consents_authenticated: false; human_approval: 'not_requested';
  chain_validated: false; authorization_allowed: false; distribution_allowed: false;
  artifact_persistence: 'no_artifact' | 'not_retained_reconstruction_requires_new_operation'; blocking_reasons: string[];
}
export interface CandidateView {
  candidate_id: Id; proposal: { proposal_id: Id; previous_proposal_id: Id | null; manifest: CandidateManifest; artifact_digest: null; effects_commitment: null; created_at: string };
  manifest_digest: string; proposal_digest: string;
  accounting: { recipient_total: Zatoshis; transaction_fee: Zatoshis; charge_total: Zatoshis; input_total: Zatoshis; output_total: Zatoshis; participant_net_debits: Record<Id, Zatoshis>; authorization_allowed: false; assurance: string; blocking_reasons: string[] };
  reviews: CandidateReview[];
  proof_jobs?: CandidateProofJob[];
}

/** Cached summary of an independent encrypted local job; never a signing grant. */
export interface CandidateProofJob {
  job_id: Id; scope_digest: string; candidate_id: Id; manifest_digest: string; coordination_request_digest: string;
  state: 'queued' | 'running' | 'uncertain' | 'succeeded' | 'failed'; attempt: number;
  input_digest: string; result_digest: string | null; effects_commitment: string; review_binding: string;
  encrypted_checkpoint_created: true; proof_verified: boolean; chain_validated: false;
  authorization_allowed: false; distribution_allowed: false; observed_at: string;
  observation_source: 'independent_encrypted_local_proof_journal';
}

/** Recovery observations are not wallet authority or a zero-exposure assertion. */
export interface RecoveryStatus {
  schema_version: 1; status: string; agreements_loaded: number; observation_stale: boolean;
  background_observation: boolean; new_authorization_allowed: boolean; authority_status: string;
  wallet_recovery: string; agreement_backup: string; message: string;
  [field: string]: unknown;
}
/** Cached metadata only. Reading it never starts or recovers a protected worker. */
export interface CandidateProofJobs {
  schema_version: 1; candidate_id: Id; observation_source: 'cached_coordination_journal';
  current_worker_liveness_known: false; authorization_allowed: false; distribution_allowed: false;
  jobs: CandidateProofJob[];
}

export interface RosterSelectionRequest { selected_intent_ids: Id[]; }
export interface ProposalChange { field: string; older: unknown; newer: unknown; }
export interface ProposalComparison {
  schema_version: 1; agreement_id: Id; older_proposal_id: Id; newer_proposal_id: Id;
  older_manifest_digest: string; newer_manifest_digest: string; material_change: boolean;
  renewed_review_required: boolean; changes: ProposalChange[]; scope: string; signable: false; message: string;
}

/** These constraints never activate a signer or grant standing spending authority. */
export type MatchAssurance = { kind: 'independently_verified' } | { kind: 'attested'; verifier_identity: Id };
export interface SponsorAccountRestriction { participant_id: Id; account_id: Id; }
export interface SponsorPolicyTerms {
  schema_version: 1; network_profile_id: string; agreement_scope: Id[];
  sponsor: SponsorAccountRestriction; eligible_contributors: SponsorAccountRestriction[];
  beneficiaries: { recipient_id: Id; address: string; maximum_amount: Zatoshis }[];
  rate_numerator: number; rate_denominator: number; maximum_match: Zatoshis;
  minimum_qualifying_total: Zatoshis; fee_cap: Zatoshis; maximum_net_debit: Zatoshis;
  aggregate_budget: Zatoshis; assurance: MatchAssurance; identity_requirements: string[];
  privacy_profile: PrivacyProfile; expires_at: string | null;
}
export type SponsorPolicyState = 'draft' | 'paused' | 'retired';
export interface SponsorPolicyView {
  agreement_id: Id; policy_id: Id; state: SponsorPolicyState; current_version: number;
  versions: { version: number; terms: SponsorPolicyTerms; terms_digest: string; previous_terms_digest: string | null; created_at: string }[];
  created_at: string; updated_at: string; authorization_allowed: false; scope: 'private_reusable_constraints_only';
}
export interface CreateSponsorPolicyRequest { policy_id: Id; terms: SponsorPolicyTerms; }
export interface UpdateSponsorPolicyRequest extends CreateSponsorPolicyRequest { expected_policy_version: number; }
export interface SponsorPolicyStateRequest { policy_id: Id; expected_policy_version: number; state: SponsorPolicyState; }
export interface SponsorPolicyPreviewRequest { candidate_id: Id; expected_policy_version: number; }
export interface SponsorPolicyMutation { policy: SponsorPolicyView; agreement_revision: number; operation_id: Id; event_sequence: number; replayed: boolean; }
export interface SponsorPolicyPreview {
  schema_version: 1; policy_agreement_id: Id; policy_id: Id; policy_version: number; policy_terms_digest: string;
  candidate_agreement_id: Id; candidate_agreement_revision: number; candidate_id: Id; candidate_manifest_digest: string;
  formula: {
    evaluation: { eligible_total: Zatoshis; calculated_match: Zatoshis; assurance: MatchAssurance; evidence_status: 'unverifiable'; authorization_allowed: false; required_evidence: string[]; limitations: string[] };
    eligible_allocations: (SponsorAccountRestriction & { contribution: Zatoshis; input_ids: Id[]; return_output_ids: Id[] })[];
    sponsor_allocation: SponsorAccountRestriction & { contribution: Zatoshis; input_ids: Id[]; return_output_ids: Id[] };
    excluded_contributions: { participant_id: Id; contribution: Zatoshis; reason: string }[];
    excluded_transaction_fee: Zatoshis; excluded_service_charges: Zatoshis; sponsor_fee_share: Zatoshis; sponsor_net_debit: Zatoshis;
    rounding: string; allocation_assurance: string;
  };
  budget: { aggregate_budget: Zatoshis; pending_authorization_exposure: Zatoshis | null; settled_debit: Zatoshis | null; remaining_budget: Zatoshis | null; status: string; reason: string };
  status: 'match_unverifiable'; authorization_allowed: false; blocking_reasons: string[];
}

/** Opaque local-runtime metadata. No keys, ciphertext, paths or witness fields. */
export interface ProtectedTransportSummary {
  handle: Id; agreement_id: Id;
  artifact_kind: 'invitation' | 'participation_intent' | 'intent_withdrawal' | 'delivery_acknowledgment' | 'proposal' | 'contribution' | 'authorization' | 'proved_proposal' | 'final_transaction' | 'settlement_evidence';
  direction: 'incoming' | 'outgoing'; artifact_fingerprint: string;
  expected_revision: number | null; idempotency_key: string | null;
  currently_valid: boolean; historical: boolean; handle_expires_at: string;
  delivery_status: string; domain_status: string; authorization_allowed: false; mailbox_storage: 'encrypted';
}

/** Safe scoped record metadata only. Never contains account, destination or receipt fields. */
export type RecordConfidence = 'no_observation' | 'outcome_uncertain' | 'pending' | 'included' | 'confirmation_policy_met' | 'stale' | 'contradictory' | 'reorganized' | 'expired_observed' | 'conflicted_observed';
export interface ParticipantRecordSummary {
  record_id: Id; agreement_id: Id; candidate_id: Id; record_revision: number;
  confidence: RecordConfidence; confirmations: number; required_confirmations: number;
  observation_sources: { source_id: Id; trust_profile_id: Id; adapter_id: Id }[];
  recovery_required: boolean; scope: 'participant_local_record_not_account_authority';
}
export interface ParticipantRecordStatus {
  status: 'available' | 'unavailable'; records: ParticipantRecordSummary[] | null;
  reason_code: string | null; account_exposure: 'unknown_not_established_by_records';
}

/** Selected inert invitation text only; receipt never creates enrollment or identity proof. */
export interface PrivateInvitation {
  schema_version: number; invitation_id: Id; organizer_key_fingerprint: string;
  invited_participant_id: Id; agreement_manifest_digest: string;
  offered_roles: ('contributor' | 'sponsor' | 'recipient' | 'reviewer')[];
  purpose: string; recipient_summary: string; fee_summary: string; visibility_summary: string;
  coordination_deadline: string;
}
export interface ProtectedInvitationView {
  summary: ProtectedTransportSummary; invitation: PrivateInvitation;
  sender_id: Id; recipient_id: Id; sender_key_fingerprint: string; recipient_key_fingerprint: string;
  original_message_id: Id; issued_at: string; expires_at: string; local_retention_id: Id;
  participant_enrolled: false; human_identity_verified: false; wallet_control_verified: false; recipient_ownership_verified: false;
}

export interface OperatorTaskHealth {
  kind: 'chain_observation' | 'transport_delivery' | 'proof_queue';
  state: 'stopped' | 'waiting' | 'running' | 'unavailable' | 'permission_lost' | 'recovery_required' | 'timed_out';
  completed_ticks: number; heartbeat_sequence: number; settlement_verified: false;
}
export interface LocalServiceHealth {
  schema_version: number; status: string; storage: string; storage_protection: string;
  signer: string; chain: string; background_observation: boolean; development_fixture: boolean;
  operator_status: 'injected' | 'not_configured'; operator_tasks: OperatorTaskHealth[] | null;
  settlement_verified: false;
}

/** Inert request metadata. This never represents native approval or a financial result. */
export interface NativeConstructionRequest { candidate_id: string; }
export interface NativeRequestView {
  schema_version: 1;
  request_id: string;
  agreement_id: string;
  candidate_id: string;
  manifest_digest: string;
  original_revision: number;
  queued_revision: number;
  attempt_revision: number | null;
  state: 'queued' | 'withdrawn' | 'attempt_started';
  authorization_allowed: false;
  result_status: 'unknown_not_financial_evidence';
}

/** Requests only native inspection and reconciliation of one retained private job. */
export interface NativeProofReconcileRequest { candidate_id: string; job_id: string; }
export interface NativeProofRequestView extends NativeRequestView {
  operation: 'proof_reconcile';
  job_id: string;
  receipt_storage_key: string;
  receipt_digest: string;
  scope_digest: string;
  coordination_request_digest: string;
  reconciliation_status: 'not_attempted' | 'unknown' | 'cached_reconciliation_recorded';
  reconciliation_operation_id: string | null;
}

/** Inert request; queued withdrawal never cancels a started prover. */
export interface NativeProofExecutionRequest { candidate_id: string; job_id: string; }
export interface NativeProofExecutionRequestView extends NativeRequestView {
  operation: 'proof_execute';
  job_id: string;
  receipt_storage_key: string;
  receipt_digest: string;
  scope_digest: string;
  coordination_request_digest: string;
  execution_status: 'not_attempted' | 'unknown' | 'durable_execution_recorded';
  execution_operation_id: string | null;
}

/** Inert exact native handoff; no approval or success is asserted. */
export interface NativeArtifactHandoffRequest { candidate_id: string; job_id: string; kind: 'signer_review' | 'signature_intake'; }
export interface NativeArtifactHandoffRequestView extends NativeRequestView {
  kind: 'signer_review' | 'signature_intake';
  proved_artifact_digest: string;
  operation: 'artifact_handoff';
  job_id: string;
  receipt_storage_key: string;
  receipt_digest: string;
  scope_digest: string;
  coordination_request_digest: string;
  handoff_status: 'not_attempted' | 'attempted_outcome_unknown';
}

/** Metadata-only handoff. Identity is derived from the original started intake. */
export type NativeSettlementRequestKind = 'signature_reconcile' | 'transaction_checkpoint';
export interface NativeSettlementRequest { intake_request_id: string; kind: NativeSettlementRequestKind; }
export interface NativeSignedObservation {
  result_id: string;
  request_digest: string;
  signed_candidate_digest: string;
  signatures_complete: boolean;
}
export type NativeSettlementObservation =
  | { type: 'signed'; evidence: NativeSignedObservation }
  | { type: 'transaction'; signed: NativeSignedObservation; checkpoint_id: string; transaction_digest: string; txid: string };
/** Historical metadata cannot establish current financial completion or chain validity. */
export interface NativeSettlementRequestView extends Omit<NativeRequestView, 'result_status'> {
  operation: 'settlement_handoff';
  result_status: 'historical_metadata_only';
  kind: NativeSettlementRequestKind;
  intake_request_id: string;
  job_id: string;
  signature_retention_key: string;
  proved_artifact_digest: string;
  receipt_storage_key: string;
  receipt_digest: string;
  scope_digest: string;
  coordination_request_digest: string;
  observation: NativeSettlementObservation | null;
  outcome_status: 'not_attempted' | 'attempted_outcome_unknown' | 'historical_result_recorded';
}

/** Inert request bound only to an original completed transaction-checkpoint request. */
export interface NativeDispatchRequest { transaction_request_id: string; }
export type NativeDispatchFailure =
  | { code: 'timeout' | 'interrupted' | 'transport_unavailable' | 'resource_limit' | 'malformed_evidence' | 'unsupported_capability' | 'other' }
  | { code: 'backend'; grpc_code: number };
export type NativeDispatchAttemptOutcome =
  | { kind: 'unknown' | 'acknowledged' | 'blocked_before_dispatch' }
  | { kind: 'rejected'; code: number }
  | { kind: 'indeterminate'; reason: NativeDispatchFailure };
export interface NativeDispatchAttempt {
  number: number;
  source_id: string;
  started_at_unix_seconds: number;
  outcome: NativeDispatchAttemptOutcome;
}
export interface NativeDispatchDescriptor {
  operation_id: string;
  obligation_id: string;
  proposal_id: string;
  transaction_id: string;
  bytes_sha256: string;
  network: 'testnet';
  expiry_height: number;
  consensus_branch_id: number;
}
export interface NativeDispatchIntent {
  operation_id: string;
  bytes_sha256: string;
  historical_provider_state: 'submission_unknown' | 'backend_acknowledged' | 'backend_rejected';
}
/** Immutable historical snapshot. An empty snapshot retains an unknown outcome. */
export interface NativeDispatchObservation {
  submission_journal_identity: string;
  descriptor: NativeDispatchDescriptor | null;
  intent: NativeDispatchIntent | null;
  attempts: NativeDispatchAttempt[];
}
/** Request/status metadata has no spending, disclosure, retry or current settlement authority. */
export interface NativeDispatchRequestView extends Omit<NativeSettlementRequestView, 'operation' | 'kind' | 'observation'> {
  operation: 'submission_dispatch';
  transaction_request_id: string;
  signed: NativeSignedObservation;
  checkpoint_id: string;
  transaction_digest: string;
  txid: string;
  operation_id: string;
  submission_journal_identity: string | null;
  observations: NativeDispatchObservation[];
}

/** Inert exact-original requests. No provider, report, private record content or authority is accepted. */
export type NativeReconciliationRequest =
  | { kind: 'provider_observation'; dispatch_request_id: string }
  | { kind: 'independent_record_resolution'; dispatch_request_id: string; participant_id: string; record_id: string };
export interface NativeReconciliationBlock { height: number; hash: string; }
/** Restored provider history is always stale and never independent settlement evidence. */
export interface NativeHistoricalReconciliationReport {
  transaction_id: string;
  expiry_height: number;
  policy: { required_confirmations: number; expiry_observation_depth: number; sources: string[] };
  observed_at_unix_seconds: number;
  valid_until_unix_seconds: number;
  state: { status: 'stale' };
  last_inclusion: NativeReconciliationBlock | null;
  confidence_lost: boolean;
  reorganization_observed: boolean;
  source_ids: string[];
  source_tips: { source_id: string; tip: NativeReconciliationBlock }[];
  independently_consensus_verified: false;
  clears_authorization_exposure: false;
  permits_replacement: false;
}
export interface NativeReconciliationObservation {
  submission: NativeDispatchObservation;
  report: NativeHistoricalReconciliationReport | null;
}
export type NativeReconciliationRequestView = Omit<NativeDispatchRequestView, 'operation' | 'submission_journal_identity' | 'observations' | 'outcome_status'> & NativeReconciliationRequest & {
  operation: 'settlement_reconciliation';
  submission_journal_identity: string;
  observations: NativeReconciliationObservation[];
  outcome_status: 'not_attempted' | 'attempted_outcome_unknown' | 'historical_observation_recorded' | 'historical_resolution_commit_recorded';
  resolution_commit: { status: 'historically_applied_independent_resolution'; observation_stale: true } | null;
};

/** Native-approved historical metadata only. No account-wide amount is inferred. */
export interface OwnerInspectionRequest { request_id:string; principal_id:string; agreement_id:string; candidate_id:string; participant_id:string; manifest_digest:string; }
export interface OwnerAuthorizationAudit { authorization_id:string; original_consent_ref:string; proposal_id:string; maximum_debit:Zatoshis; transaction_expiry_height:number; result_retained:boolean; latest_settlement_record:'canonical_consumed'|'canonical_conflict'|'reopened'|null; automation_grant_id:string|null; }
export interface OwnerSponsorAudit { policy_key:string; version:number; terms_digest:string; status:'active'|'paused'|'revoked'; aggregate_budget:Zatoshis; expires_at:string|null; witness_id:string; witness_policy_digest:string; }
export interface OwnerAutomationAudit { grant_id:string; application_id:string; revision:number; terms_digest:string; status:'draft'|'active'|'paused'|'revoked'|'expired'; maximum_payment_debit:Zatoshis; maximum_outstanding_debit:Zatoshis; expires_at_ms:number; }
export interface OwnerInspectionSnapshot { schema_version:1; request:OwnerInspectionRequest; account_id:string; source_principal_id:string; writer_epoch:number; recovery_required:boolean; inspected_at_ms:number; provenance:'native_owner_approved_local_signer_journal'; freshness:'historical_local_snapshot_no_live_witness_or_chain_observation'; authorization_allowed:false; balance:null; account_pending_exposure:null; account_settled_debit:null; account_remaining_budget:null; authorizations:OwnerAuthorizationAudit[]; sponsor_policies:OwnerSponsorAudit[]; automation_grants:OwnerAutomationAudit[]; }
export interface NativeAccountInspectionRequest { candidate_id:string; participant_id:string; }
export interface NativeAccountInspectionRequestView { schema_version:1; operation:'owner_account_inspection'; request:OwnerInspectionRequest; original_revision:number; queued_revision:number; attempt_revision:number|null; state:'queued'|'withdrawn'|'attempt_started'; result_status:'historical_native_approved_metadata'|'unknown_no_committed_result'; authorization_allowed:false; result:OwnerInspectionSnapshot|null; }
