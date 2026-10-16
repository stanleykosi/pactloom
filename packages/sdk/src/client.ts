import { ownerInspectionMetadata } from './owner-inspection-metadata.js';
import type { NativeAccountInspectionRequest, NativeAccountInspectionRequestView } from './types.js';
import { nativeReconciliationRequestMetadata, nativeReconciliationInput } from './native-reconciliation-metadata.js';
import { nativeDispatchRequestMetadata } from './native-dispatch-metadata.js';
import { nativeSettlementRequestMetadata } from './native-settlement-metadata.js';
import type { NativeReconciliationRequest, NativeReconciliationRequestView, NativeDispatchRequest, NativeDispatchRequestView, NativeSettlementRequest, NativeSettlementRequestView, NativeArtifactHandoffRequest, NativeArtifactHandoffRequestView, NativeProofExecutionRequest, NativeProofExecutionRequestView, NativeProofReconcileRequest, NativeProofRequestView, NativeConstructionRequest, NativeRequestView, AccountRecord, AgreementDraft, AgreementView, ApiErrorBody, AuthorizationRecord, CapabilitySet, CandidateRequest, CandidateView, MutationOptions, Operation, ParticipationIntent, Session, ParticipantRecordStatus, WholepactEvent, ProposalPreview, RecoveryStatus, CandidateProofJobs, RosterSelectionRequest, ProposalComparison, SponsorPolicyView, CreateSponsorPolicyRequest, UpdateSponsorPolicyRequest, SponsorPolicyStateRequest, SponsorPolicyPreviewRequest, SponsorPolicyMutation, SponsorPolicyPreview, ProtectedTransportSummary, ProtectedInvitationView, LocalServiceHealth } from './types.js';

export class WholepactError extends Error {
  readonly code: string; readonly retryable: boolean; readonly operationId: string | null;
  readonly safeActions: string[]; readonly details: unknown; readonly status: number; readonly requestId: string;
  constructor(body: ApiErrorBody, status = 0, requestId = '') {
    super(body.message); this.name = 'WholepactError'; this.code = body.code;
    this.retryable = body.retryable; this.operationId = body.operation_id ?? null;
    this.safeActions = body.safe_actions ?? []; this.details = body.details;
    this.status = status; this.requestId = requestId;
  }
}
export interface ClientOptions { baseUrl?: string; token: string; fetch?: typeof globalThis.fetch; }
/** Loopback-only client. A remote coordinator requires a different scoped API. */
export class WholepactClient {
  readonly baseUrl: string;
  #token: string; #csrf = ''; #fetch: typeof globalThis.fetch;
  constructor({ baseUrl = 'http://127.0.0.1:4318/v1', token, fetch: fetcher = globalThis.fetch }: ClientOptions) {
    const url = new URL(baseUrl);
    if (!['127.0.0.1', 'localhost', '[::1]'].includes(url.hostname) || !['http:', 'https:'].includes(url.protocol) || url.username || url.password || url.search || url.hash) {
      throw new Error('The local workspace connects only to a loopback Wholepact service.');
    }
    if (!token.trim() || /[\r\n]/.test(token)) throw new Error('Enter the local service session token.');
    this.baseUrl = url.href.replace(/\/$/, ''); this.#token = token; this.#fetch = fetcher.bind(globalThis);
  }
  /** Clears credentials owned by this instance. Tokens are never written to browser storage. */
  disconnect(): void { this.#token = ''; this.#csrf = ''; }
  async endSession(): Promise<void> {
    const pending = this.request('/session/end', { method: 'POST', body: {} });
    this.disconnect();
    await pending;
  }
  async connect(signal?: AbortSignal): Promise<Session> {
    const session = await this.request<Session>('/session', { signal });
    if (typeof session.session_token !== 'string' || !session.session_token || typeof session.csrf_token !== 'string' || !session.csrf_token) throw new Error('Local service did not issue a CSRF session.');
    this.#token = session.session_token; this.#csrf = session.csrf_token; return session;
  }
  capabilities(signal?: AbortSignal): Promise<CapabilitySet> { return this.request('/capabilities', { signal }); }
  health(signal?: AbortSignal): Promise<LocalServiceHealth> { return this.request('/health', { signal }); }
  agreements(signal?: AbortSignal): Promise<AgreementView[]> { return this.request('/agreements', { signal }); }
  agreement(id: string, signal?: AbortSignal): Promise<AgreementView> { return this.request(`/agreements/${resourceId(id)}`, { signal }); }
  validateAgreement(draft: AgreementDraft, signal?: AbortSignal): Promise<unknown> { return this.request('/agreements/validate', { method: 'POST', body: draft, signal, readOnly: true }); }
  createAgreement(draft: AgreementDraft, options: MutationOptions): Promise<AgreementView> { return this.mutate('/agreements', draft, options); }
  /** Append complete unsigned terms. expectedRevision is the journal revision, not draft.revision.
   * Retain the exact draft, key and opening revision until an interrupted result is resolved. */
  reviseAgreement(id: string, draft: AgreementDraft, options: MutationOptions & { expectedRevision: number }): Promise<AgreementView> {
    if (!Number.isSafeInteger(options.expectedRevision) || options.expectedRevision < 1 || options.expectedRevision >= Number.MAX_SAFE_INTEGER) throw new Error('An exact positive journal revision is required.');
    const journalRevision = options.expectedRevision; const idempotencyKey = options.idempotencyKey;
    const path = `/agreements/${resourceId(id)}/terms-revisions`;
    // Snapshot at dispatch: caller mutation must never change the success binding.
    const submitted = JSON.stringify(draft);
    this.checkMutationOptions(options);
    return this.request<AgreementView>(path, { method: 'POST', jsonSource: submitted, signal: options.signal, idempotencyKey, expectedRevision: journalRevision })
      .then(value => {
        if (!value || !value.agreement || value.agreement.agreement_id !== id || canonicalJson(value.agreement) !== canonicalJson(JSON.parse(submitted)) || value.revision !== journalRevision + 1 || (value.terms_history !== undefined && !Array.isArray(value.terms_history)) || (value.terms_editability !== undefined && (typeof value.terms_editability?.allowed !== 'boolean' || typeof value.terms_editability.reason !== 'string'))) {
          throw new WholepactError({ code: 'EXTERNAL_OUTCOME_UNCERTAIN', message: 'The saved terms revision could not be established. Retry only the exact original body, idempotency key and journal revision.', retryable: false, details: { resource: path, idempotency_key: idempotencyKey, expected_revision: journalRevision } });
        }
        return value;
      });
  }
  recordIntent(id: string, intent: ParticipationIntent, options: MutationOptions): Promise<AgreementView> { return this.mutate(`/agreements/${resourceId(id)}/intents`, intent, options); }
  withdrawIntent(id: string, intentId: string, options: MutationOptions): Promise<AgreementView> { return this.mutate(`/agreements/${resourceId(id)}/intents/${resourceId(intentId)}/withdraw`, {}, options); }
  invitations(signal?: AbortSignal): Promise<ProtectedTransportSummary[]> { return this.request('/invitations', { signal }); }
  invitation(handle: string, signal?: AbortSignal): Promise<ProtectedInvitationView> { return this.request(`/invitations/${resourceId(handle)}`, { signal }); }
  stagedTransport(agreementId: string, signal?: AbortSignal): Promise<ProtectedTransportSummary[]> { return this.request(`/agreements/${resourceId(agreementId)}/transport`, { signal }); }
  transportPreview(agreementId: string, handle: string, signal?: AbortSignal): Promise<ProtectedTransportSummary> { return this.request(`/agreements/${resourceId(agreementId)}/transport/${resourceId(handle)}`, { signal }); }
  importTransport(agreementId: string, handle: string, options: MutationOptions): Promise<AgreementView> { return this.mutate(`/agreements/${resourceId(agreementId)}/transport/${resourceId(handle)}/import`, {}, options); }
  async nativeAccountInspectionRequests(agreement:string, signal?:AbortSignal): Promise<NativeAccountInspectionRequestView[]> {
    if (typeof agreement !== 'string') throw new Error('Supply the exact selected agreement ID.');
    return ownerInspectionMetadata(await this.request(`/agreements/${resourceId(agreement)}/native-account-inspection-requests`, { signal }), agreement);
  }
  async nativeAccountInspectionRequest(agreement:string, requestId:string, signal?:AbortSignal): Promise<NativeAccountInspectionRequestView> {
    if (typeof agreement !== 'string' || typeof requestId !== 'string' || !/^[a-f0-9]{64}$/.test(requestId)) throw new Error('Supply the exact agreement and original inspection request ID.');
    const value = ownerInspectionMetadata([await this.request(`/agreements/${resourceId(agreement)}/native-account-inspection-requests/${resourceId(requestId)}`, { signal })], agreement)[0];
    if (!value || value.request.request_id !== requestId) throw new WholepactError({ code:'INVALID_RESPONSE', message:'Original inspection request identity changed.', retryable:false });
    return value;
  }
  requestNativeAccountInspection(agreement:string, request:NativeAccountInspectionRequest, options:MutationOptions & { expectedRevision:number }): Promise<NativeAccountInspectionRequestView> {
    if (!request || typeof request !== 'object' || Array.isArray(request)) return Promise.reject(new Error('Choose an exact candidate and participant.'));
    return this.changeAccountInspection(agreement, request, options);
  }
  withdrawNativeAccountInspection(agreement:string, requestId:string, options:MutationOptions & { expectedRevision:number }): Promise<NativeAccountInspectionRequestView> {
    if (typeof requestId !== 'string' || !/^[a-f0-9]{64}$/.test(requestId)) return Promise.reject(new Error('Supply the exact original inspection request ID.'));
    return this.changeAccountInspection(agreement, undefined, options, requestId);
  }
  private async changeAccountInspection(agreement:string, input:NativeAccountInspectionRequest|undefined, options:MutationOptions & { expectedRevision:number }, withdrawal?:string): Promise<NativeAccountInspectionRequestView> {
    if (typeof agreement !== 'string') throw new Error('Supply the exact selected agreement ID.');
    const request = input && { ...input }; const revision = options.expectedRevision; const key = options.idempotencyKey;
    if (!Number.isSafeInteger(revision) || revision < 1 || revision >= Number.MAX_SAFE_INTEGER) throw new Error('An exact positive journal revision is required.');
    if (request && (Object.keys(request).length !== 2 || typeof request.candidate_id !== 'string' || typeof request.participant_id !== 'string' || !/^[A-Za-z0-9_.:-]{1,128}$/.test(request.candidate_id) || !/^[A-Za-z0-9_.:-]{1,128}$/.test(request.participant_id) || ['.','..'].includes(request.candidate_id) || ['.','..'].includes(request.participant_id))) throw new Error('Choose an exact candidate and participant; account IDs and approval fields are not accepted.');
    const path = `/agreements/${resourceId(agreement)}/native-account-inspection-requests${withdrawal ? `/${resourceId(withdrawal)}/withdraw` : ''}`;
    const raw = await this.mutate(path, request ?? {}, { ...options, idempotencyKey:key, expectedRevision:revision });
    try {
      const result = ownerInspectionMetadata([raw], agreement)[0];
      if (!result) throw new Error('Missing result');
      if (withdrawal ? result.request.request_id !== withdrawal || result.state !== 'withdrawn' : result.original_revision !== revision || result.request.candidate_id !== request!.candidate_id || result.request.participant_id !== request!.participant_id) throw new Error('Binding mismatch');
      return result;
    } catch {
      throw new WholepactError({ code:'EXTERNAL_OUTCOME_UNCERTAIN', message:'Inspection acknowledgement is unverified. Preserve the exact original body, key and journal revision; retry only that original request.', retryable:false, details:{ agreement_id:agreement, idempotency_key:key, expected_revision:revision, request_id:withdrawal, request } });
    }
  }
  sponsorPolicies(agreementId: string, signal?: AbortSignal): Promise<SponsorPolicyView[]> { return this.request(`/agreements/${resourceId(agreementId)}/sponsor-policies`, { signal }); }
  sponsorPolicy(agreementId: string, policyId: string, signal?: AbortSignal): Promise<SponsorPolicyView> { return this.request(`/agreements/${resourceId(agreementId)}/sponsor-policies/${resourceId(policyId)}`, { signal }); }
  createSponsorPolicy(agreementId: string, request: CreateSponsorPolicyRequest, options: MutationOptions): Promise<SponsorPolicyMutation> { return this.mutate(`/agreements/${resourceId(agreementId)}/sponsor-policies`, request, options); }
  updateSponsorPolicy(agreementId: string, request: UpdateSponsorPolicyRequest, options: MutationOptions): Promise<SponsorPolicyMutation> { return this.mutate(`/agreements/${resourceId(agreementId)}/sponsor-policies/${resourceId(request.policy_id)}/versions`, request, options); }
  setSponsorPolicyState(agreementId: string, request: SponsorPolicyStateRequest, options: MutationOptions): Promise<SponsorPolicyMutation> { return this.mutate(`/agreements/${resourceId(agreementId)}/sponsor-policies/${resourceId(request.policy_id)}/state`, request, options); }
  previewSponsorPolicy(agreementId: string, policyId: string, request: SponsorPolicyPreviewRequest, signal?: AbortSignal): Promise<SponsorPolicyPreview> { return this.request(`/agreements/${resourceId(agreementId)}/sponsor-policies/${resourceId(policyId)}/preview`, { method: 'POST', body: request, signal, readOnly: true }); }
  /** Preserve source JSON for the service's duplicate-key and unknown-field checks. */
  saveSponsorPolicySource(agreementId: string, policyId: string, termsSource: string, options: MutationOptions, expectedPolicyVersion?: number): Promise<SponsorPolicyMutation> {
    if (new TextEncoder().encode(termsSource).length > 250_000) throw new Error('Sponsor terms exceed the bounded editor size.');
    this.checkMutationOptions(options);
    if (expectedPolicyVersion !== undefined && (!Number.isSafeInteger(expectedPolicyVersion) || expectedPolicyVersion < 1)) throw new Error('Invalid sponsor policy version.');
    const source = `{"policy_id":${JSON.stringify(resourceId(policyId))},${expectedPolicyVersion === undefined ? '' : `"expected_policy_version":${expectedPolicyVersion},`}"terms":${termsSource}}`;
    return this.request(`/agreements/${resourceId(agreementId)}/sponsor-policies${expectedPolicyVersion === undefined ? '' : `/${resourceId(policyId)}/versions`}`, { method: 'POST', jsonSource: source, signal: options.signal, idempotencyKey: options.idempotencyKey, expectedRevision: options.expectedRevision });
  }
  selectRoster(id: string, selection: RosterSelectionRequest, options: MutationOptions): Promise<AgreementView> { return this.mutate(`/agreements/${resourceId(id)}/roster-selection`, selection, options); }
  compareProposals(olderId: string, newerId: string, signal?: AbortSignal): Promise<ProposalComparison> { return this.request(`/proposals/${resourceId(newerId)}/compare/${resourceId(olderId)}`, { signal }); }
  compareCandidates(olderId: string, newerId: string, signal?: AbortSignal): Promise<ProposalComparison> { return this.request(`/candidates/${resourceId(newerId)}/compare/${resourceId(olderId)}`, { signal }); }
  createCandidate(id: string, candidate: CandidateRequest, options: MutationOptions): Promise<AgreementView> { return this.mutate(`/agreements/${resourceId(id)}/candidates`, candidate, options); }
  candidate(id: string, signal?: AbortSignal): Promise<CandidateView> { return this.request(`/candidates/${resourceId(id)}`, { signal }); }
  /** Enqueues metadata only. Stop the service and review the request in the native host separately. */
  requestNativeConstruction(agreementId: string, request: NativeConstructionRequest, options: MutationOptions): Promise<NativeRequestView> {
    resourceId(request.candidate_id);
    if (options.expectedRevision === undefined) throw new Error('An exact agreement revision is required.');
    return this.mutate<NativeRequestView>(`/agreements/${resourceId(agreementId)}/native-requests`, request, options)
      .then(value => this.nativeRequestResponse(value, agreementId, options, request.candidate_id));
  }
  nativeRequests(agreementId: string, signal?: AbortSignal): Promise<NativeRequestView[]> {
    return this.request(`/agreements/${resourceId(agreementId)}/native-requests`, { signal });
  }
  nativeRequest(agreementId: string, requestId: string, signal?: AbortSignal): Promise<NativeRequestView> {
    return this.request(`/agreements/${resourceId(agreementId)}/native-requests/${resourceId(requestId)}`, { signal });
  }
  withdrawNativeRequest(agreementId: string, requestId: string, options: MutationOptions): Promise<NativeRequestView> {
    if (options.expectedRevision === undefined) throw new Error('An exact agreement revision is required.');
    return this.mutate<NativeRequestView>(`/agreements/${resourceId(agreementId)}/native-requests/${resourceId(requestId)}/withdraw`, {}, options)
      .then(value => this.nativeRequestResponse(value, agreementId, options, undefined, requestId));
  }
  /** Queue exact metadata only. Native observation and independent record resolution remain separate. */
  requestNativeReconciliation(agreementId: string, request: NativeReconciliationRequest, options: MutationOptions): Promise<NativeReconciliationRequestView> {
    if (typeof agreementId !== 'string') throw new Error('Supply the exact selected agreement ID.');
    const original = nativeReconciliationInput(request);
    if (options.expectedRevision === undefined) throw new Error('An exact agreement revision is required.');
    const command = { ...options };
    return this.mutate<NativeReconciliationRequestView>(`/agreements/${resourceId(agreementId)}/native-reconciliation-requests`, original, command)
      .then(value => this.nativeReconciliationResponse(value, agreementId, command, original));
  }
  nativeReconciliationRequests(agreementId: string, signal?: AbortSignal): Promise<NativeReconciliationRequestView[]> {
    if (typeof agreementId !== 'string') throw new Error('Supply the exact selected agreement ID.');
    return this.request<NativeReconciliationRequestView[]>(`/agreements/${resourceId(agreementId)}/native-reconciliation-requests`, { signal }).then(values => {
      try { return nativeReconciliationRequestMetadata(values, agreementId); }
      catch { throw new WholepactError({ code: 'INVALID_RESPONSE', message: 'Invalid retained reconciliation history. Preserve every original native journal.', retryable: false }); }
    });
  }
  nativeReconciliationRequest(agreementId: string, requestId: string, signal?: AbortSignal): Promise<NativeReconciliationRequestView> {
    if (typeof agreementId !== 'string') throw new Error('Supply the exact selected agreement ID.');
    if (typeof requestId !== 'string' || !/^[0-9a-f]{64}$/.test(requestId)) throw new Error('Supply the exact original reconciliation request ID.');
    return this.request<NativeReconciliationRequestView>(`/agreements/${resourceId(agreementId)}/native-reconciliation-requests/${requestId}`, { signal }).then(value => {
      const checked = this.nativeReconciliationResponse(value, agreementId);
      if (checked.request_id !== requestId) throw new WholepactError({ code: 'INVALID_RESPONSE', message: 'Retained reconciliation identity differs from the requested identity.', retryable: false });
      return checked;
    });
  }
  withdrawNativeReconciliationRequest(agreementId: string, requestId: string, options: MutationOptions): Promise<NativeReconciliationRequestView> {
    if (typeof agreementId !== 'string') throw new Error('Supply the exact selected agreement ID.');
    if (typeof requestId !== 'string' || !/^[0-9a-f]{64}$/.test(requestId)) throw new Error('Supply the exact original reconciliation request ID.');
    if (options.expectedRevision === undefined) throw new Error('An exact agreement revision is required.');
    const command = { ...options };
    return this.mutate<NativeReconciliationRequestView>(`/agreements/${resourceId(agreementId)}/native-reconciliation-requests/${requestId}/withdraw`, {}, command)
      .then(value => this.nativeReconciliationResponse(value, agreementId, command, undefined, requestId));
  }
  private nativeReconciliationResponse(value: NativeReconciliationRequestView, agreement: string, options?: MutationOptions, request?: NativeReconciliationRequest, withdrawal?: string): NativeReconciliationRequestView {
    try {
      nativeReconciliationRequestMetadata([value], agreement);
      if (request && (value.dispatch_request_id !== request.dispatch_request_id || value.kind !== request.kind
        || value.original_revision !== options?.expectedRevision
        || request.kind === 'independent_record_resolution' && (value.kind !== 'independent_record_resolution'
          || value.participant_id !== request.participant_id || value.record_id !== request.record_id))) throw new Error('Changed exact original reconciliation binding.');
      if (withdrawal !== undefined && (value.request_id !== withdrawal || value.state !== 'withdrawn')) throw new Error('Never-started withdrawal was not established.');
    } catch {
      throw new WholepactError({ code: options ? 'EXTERNAL_OUTCOME_UNCERTAIN' : 'INVALID_RESPONSE', message: 'Exact reconciliation acknowledgement was not established. Preserve the original command and stop/drain the service before native-reconciliation-status. Do not reset or replace this request.', retryable: false, details: { idempotency_key: options?.idempotencyKey, agreement_id: agreement, dispatch_request_id: request?.dispatch_request_id, kind: request?.kind, participant_id: request?.kind === 'independent_record_resolution' ? request.participant_id : undefined, record_id: request?.kind === 'independent_record_resolution' ? request.record_id : undefined, request_id: withdrawal, expected_revision: options?.expectedRevision } });
    }
    return value;
  }
  /** Queue metadata only; the original transaction-checkpoint request is the sole input. No dispatch occurs here. */
  requestNativeDispatch(agreementId: string, request: NativeDispatchRequest, options: MutationOptions): Promise<NativeDispatchRequestView> {
    if (typeof agreementId !== 'string') throw new Error('Supply the exact selected agreement ID.');
    if (!request || typeof request !== 'object' || Array.isArray(request) || Object.keys(request).length !== 1
      || !Object.hasOwn(request, 'transaction_request_id') || typeof request.transaction_request_id !== 'string'
      || !/^[0-9a-f]{64}$/.test(request.transaction_request_id)) throw new Error('Supply only the original transaction-checkpoint request ID.');
    if (options.expectedRevision === undefined) throw new Error('An exact agreement revision is required.');
    // Copy the checked scalar, so subsequent caller mutation cannot change the response binding.
    const original = { transaction_request_id: request.transaction_request_id };
    const command = { ...options };
    return this.mutate<NativeDispatchRequestView>(`/agreements/${resourceId(agreementId)}/native-dispatch-requests`, original, command)
      .then(value => this.nativeDispatchResponse(value, agreementId, command, original));
  }
  nativeDispatchRequests(agreementId: string, signal?: AbortSignal): Promise<NativeDispatchRequestView[]> {
    if (typeof agreementId !== 'string') throw new Error('Supply the exact selected agreement ID.');
    return this.request<NativeDispatchRequestView[]>(`/agreements/${resourceId(agreementId)}/native-dispatch-requests`, { signal }).then(values => {
      try { return nativeDispatchRequestMetadata(values, agreementId); }
      catch { throw new WholepactError({ code: 'INVALID_RESPONSE', message: 'Invalid retained dispatch history. Preserve the original native journals.', retryable: false }); }
    });
  }
  nativeDispatchRequest(agreementId: string, requestId: string, signal?: AbortSignal): Promise<NativeDispatchRequestView> {
    if (typeof agreementId !== 'string') throw new Error('Supply the exact selected agreement ID.');
    if (typeof requestId !== 'string' || !/^[0-9a-f]{64}$/.test(requestId)) throw new Error('Supply the exact original dispatch request ID.');
    return this.request<NativeDispatchRequestView>(`/agreements/${resourceId(agreementId)}/native-dispatch-requests/${requestId}`, { signal }).then(value => {
      const checked = this.nativeDispatchResponse(value, agreementId);
      if (checked.request_id !== requestId) throw new WholepactError({ code: 'INVALID_RESPONSE', message: 'Retained dispatch request identity differs from the requested identity.', retryable: false });
      return checked;
    });
  }
  withdrawNativeDispatchRequest(agreementId: string, requestId: string, options: MutationOptions): Promise<NativeDispatchRequestView> {
    if (typeof agreementId !== 'string') throw new Error('Supply the exact selected agreement ID.');
    if (typeof requestId !== 'string' || !/^[0-9a-f]{64}$/.test(requestId)) throw new Error('Supply the exact original dispatch request ID.');
    if (options.expectedRevision === undefined) throw new Error('An exact agreement revision is required.');
    const command = { ...options };
    return this.mutate<NativeDispatchRequestView>(`/agreements/${resourceId(agreementId)}/native-dispatch-requests/${requestId}/withdraw`, {}, command)
      .then(value => this.nativeDispatchResponse(value, agreementId, command, undefined, requestId));
  }
  private nativeDispatchResponse(value: NativeDispatchRequestView, agreement: string, options?: MutationOptions, request?: NativeDispatchRequest, withdrawal?: string): NativeDispatchRequestView {
    try {
      nativeDispatchRequestMetadata([value], agreement);
      if (request && (value.transaction_request_id !== request.transaction_request_id || value.original_revision !== options?.expectedRevision)) throw new Error('Changed original transaction binding.');
      if (withdrawal !== undefined && (value.request_id !== withdrawal || value.state !== 'withdrawn')) throw new Error('Never-started withdrawal was not established.');
    } catch {
      throw new WholepactError({ code: options ? 'EXTERNAL_OUTCOME_UNCERTAIN' : 'INVALID_RESPONSE', message: 'Exact dispatch request response was not established. Preserve the original command and inspect native-dispatch-status after service stop/drain; do not create a replacement.', retryable: false, details: { idempotency_key: options?.idempotencyKey, agreement_id: agreement, transaction_request_id: request?.transaction_request_id, request_id: withdrawal, expected_revision: options?.expectedRevision } });
    }
    return value;
  }
  /** Queue metadata only. The original started signature intake is the sole input identity. */
  requestNativeSettlement(agreementId: string, request: NativeSettlementRequest, options: MutationOptions): Promise<NativeSettlementRequestView> {
    if (!request || Object.keys(request).length !== 2 || !Object.hasOwn(request, 'intake_request_id') || !Object.hasOwn(request, 'kind')
      || typeof request.intake_request_id !== 'string' || !/^[0-9a-f]{64}$/.test(request.intake_request_id)
      || !['signature_reconcile', 'transaction_checkpoint'].includes(request.kind)) throw new Error('Supply only the original signature-intake request ID and settlement request kind.');
    if (options.expectedRevision === undefined) throw new Error('An exact agreement revision is required.');
    return this.mutate<NativeSettlementRequestView>(`/agreements/${resourceId(agreementId)}/native-settlement-requests`, request, options)
      .then(value => this.nativeSettlementResponse(value, agreementId, options, request));
  }
  nativeSettlementRequests(agreementId: string, signal?: AbortSignal): Promise<NativeSettlementRequestView[]> {
    return this.request<NativeSettlementRequestView[]>(`/agreements/${resourceId(agreementId)}/native-settlement-requests`, { signal }).then(values => {
      try { return nativeSettlementRequestMetadata(values, agreementId); }
      catch { throw new WholepactError({ code: 'INVALID_RESPONSE', message: 'Invalid retained settlement request inventory. Inspect the original native journals.', retryable: false }); }
    });
  }
  nativeSettlementRequest(agreementId: string, requestId: string, signal?: AbortSignal): Promise<NativeSettlementRequestView> {
    return this.request<NativeSettlementRequestView>(`/agreements/${resourceId(agreementId)}/native-settlement-requests/${resourceId(requestId)}`, { signal }).then(value => {
      const checked = this.nativeSettlementResponse(value, agreementId);
      if (checked.request_id !== requestId) throw new WholepactError({ code: 'INVALID_RESPONSE', message: 'Retained settlement request identity differs from the requested identity.', retryable: false });
      return checked;
    });
  }
  withdrawNativeSettlementRequest(agreementId: string, requestId: string, options: MutationOptions): Promise<NativeSettlementRequestView> {
    if (options.expectedRevision === undefined) throw new Error('An exact agreement revision is required.');
    return this.mutate<NativeSettlementRequestView>(`/agreements/${resourceId(agreementId)}/native-settlement-requests/${resourceId(requestId)}/withdraw`, {}, options)
      .then(value => this.nativeSettlementResponse(value, agreementId, options, undefined, requestId));
  }
  private nativeSettlementResponse(value: NativeSettlementRequestView, agreement: string, options?: MutationOptions, request?: NativeSettlementRequest, withdrawal?: string): NativeSettlementRequestView {
    try {
      nativeSettlementRequestMetadata([value], agreement);
      if (request && (value.intake_request_id !== request.intake_request_id || value.kind !== request.kind || value.original_revision !== options?.expectedRevision)) throw new Error('Changed request binding.');
      if (withdrawal !== undefined && (value.request_id !== withdrawal || value.state !== 'withdrawn')) throw new Error('Withdrawal was not established.');
    } catch {
      throw new WholepactError({ code: options ? 'EXTERNAL_OUTCOME_UNCERTAIN' : 'INVALID_RESPONSE', message: 'Exact settlement request response was not established. Preserve the original request and inspect the native host; do not create a replacement.', retryable: false, details: { idempotency_key: options?.idempotencyKey, agreement_id: agreement, intake_request_id: request?.intake_request_id, expected_revision: options?.expectedRevision } });
    }
    return value;
  }
  /** Request an exact native signer-review or signature-intake handoff after service stop/drain; no browser approval. */
  requestNativeArtifactHandoff(agreementId: string, request: NativeArtifactHandoffRequest, options: MutationOptions): Promise<NativeArtifactHandoffRequestView> {
    resourceId(request.candidate_id); resourceId(request.job_id);
    if (options.expectedRevision === undefined) throw new Error('An exact agreement revision is required.');
    return this.mutate<NativeArtifactHandoffRequestView>(`/agreements/${resourceId(agreementId)}/native-artifact-handoff-requests`, request, options)
      .then(value => this.nativeArtifactHandoffRequestResponse(value, agreementId, options, request.candidate_id, request.job_id, undefined, request.kind));
  }
  nativeArtifactHandoffRequests(agreementId: string, signal?: AbortSignal): Promise<NativeArtifactHandoffRequestView[]> {
    return this.request<NativeArtifactHandoffRequestView[]>(`/agreements/${resourceId(agreementId)}/native-artifact-handoff-requests`, { signal }).then(values => {
      if (!Array.isArray(values) || values.length > 16 || new Set(values.map(value => value?.request_id)).size !== values.length) {
        throw new WholepactError({code:'INVALID_RESPONSE',message:'Invalid retained artifact handoff inventory.',retryable:false});
      }
      return values.map(value => this.nativeArtifactHandoffRequestResponse(value, agreementId));
    });
  }
  nativeArtifactHandoffRequest(agreementId: string, requestId: string, signal?: AbortSignal): Promise<NativeArtifactHandoffRequestView> {
    return this.request<NativeArtifactHandoffRequestView>(`/agreements/${resourceId(agreementId)}/native-artifact-handoff-requests/${resourceId(requestId)}`, { signal }).then(value => {
      const checked = this.nativeArtifactHandoffRequestResponse(value, agreementId);
      if (checked.request_id !== requestId) throw new WholepactError({code:'INVALID_RESPONSE',message:'Retained artifact handoff identity differs from the requested identity.',retryable:false});
      return checked;
    });
  }
  withdrawNativeArtifactHandoffRequest(agreementId: string, requestId: string, options: MutationOptions): Promise<NativeArtifactHandoffRequestView> {
    if (options.expectedRevision === undefined) throw new Error('An exact agreement revision is required.');
    return this.mutate<NativeArtifactHandoffRequestView>(`/agreements/${resourceId(agreementId)}/native-artifact-handoff-requests/${resourceId(requestId)}/withdraw`, {}, options)
      .then(value => this.nativeArtifactHandoffRequestResponse(value, agreementId, options, undefined, undefined, requestId));
  }
  private nativeArtifactHandoffRequestResponse(value: NativeArtifactHandoffRequestView, agreement: string, options?: MutationOptions, candidate?: string, job?: string, withdrawal?: string, kind?: NativeArtifactHandoffRequest['kind']): NativeArtifactHandoffRequestView {
    this.nativeRequestResponse(value, agreement, options, candidate, withdrawal);
    const digest = (value: unknown) => typeof value === 'string' && /^[0-9a-f]{64}$/.test(value);
    if (value.operation !== 'artifact_handoff' || typeof value.job_id !== 'string' || !/^proof-[0-9a-f]{64}$/.test(value.job_id)
      || (job !== undefined && value.job_id !== job)
      || !['signer_review','signature_intake'].includes(value.kind)
      || (kind !== undefined && value.kind !== kind)
      || !digest(value.proved_artifact_digest)
      || ![value.receipt_storage_key, value.receipt_digest, value.scope_digest, value.coordination_request_digest].every(digest)
      || !['not_attempted', 'attempted_outcome_unknown'].includes(value.handoff_status)
      || (value.state === 'attempt_started' ? value.handoff_status === 'not_attempted' : value.handoff_status !== 'not_attempted')
) {
      throw new WholepactError({ code: options ? 'EXTERNAL_OUTCOME_UNCERTAIN' : 'INVALID_RESPONSE', message: 'Exact native handoff response was not established. Preserve the original request and inspect the native host.', retryable: false, details: {idempotency_key: options?.idempotencyKey, agreement_id: agreement, job_id: job} });
    }
    return value;
  }
  /** Request native proof execution only; fresh private proof consent is required after service stop/drain. Never retries or cancels a started worker. */
  requestNativeProofExecution(agreementId: string, request: NativeProofExecutionRequest, options: MutationOptions): Promise<NativeProofExecutionRequestView> {
    resourceId(request.candidate_id); resourceId(request.job_id);
    if (options.expectedRevision === undefined) throw new Error('An exact agreement revision is required.');
    return this.mutate<NativeProofExecutionRequestView>(`/agreements/${resourceId(agreementId)}/native-proof-execution-requests`, request, options)
      .then(value => this.nativeProofExecutionRequestResponse(value, agreementId, options, request.candidate_id, request.job_id));
  }
  nativeProofExecutionRequests(agreementId: string, signal?: AbortSignal): Promise<NativeProofExecutionRequestView[]> {
    return this.request<NativeProofExecutionRequestView[]>(`/agreements/${resourceId(agreementId)}/native-proof-execution-requests`, { signal }).then(values => {
      if (!Array.isArray(values) || values.length > 16 || new Set(values.map(value => value?.request_id)).size !== values.length) {
        throw new WholepactError({code:'INVALID_RESPONSE',message:'Invalid retained proof request inventory.',retryable:false});
      }
      return values.map(value => this.nativeProofExecutionRequestResponse(value, agreementId));
    });
  }
  nativeProofExecutionRequest(agreementId: string, requestId: string, signal?: AbortSignal): Promise<NativeProofExecutionRequestView> {
    return this.request<NativeProofExecutionRequestView>(`/agreements/${resourceId(agreementId)}/native-proof-execution-requests/${resourceId(requestId)}`, { signal }).then(value => {
      const checked = this.nativeProofExecutionRequestResponse(value, agreementId);
      if (checked.request_id !== requestId) throw new WholepactError({code:'INVALID_RESPONSE',message:'Retained proof request identity differs from the requested identity.',retryable:false});
      return checked;
    });
  }
  withdrawNativeProofExecutionRequest(agreementId: string, requestId: string, options: MutationOptions): Promise<NativeProofExecutionRequestView> {
    if (options.expectedRevision === undefined) throw new Error('An exact agreement revision is required.');
    return this.mutate<NativeProofExecutionRequestView>(`/agreements/${resourceId(agreementId)}/native-proof-execution-requests/${resourceId(requestId)}/withdraw`, {}, options)
      .then(value => this.nativeProofExecutionRequestResponse(value, agreementId, options, undefined, undefined, requestId));
  }
  private nativeProofExecutionRequestResponse(value: NativeProofExecutionRequestView, agreement: string, options?: MutationOptions, candidate?: string, job?: string, withdrawal?: string): NativeProofExecutionRequestView {
    this.nativeRequestResponse(value, agreement, options, candidate, withdrawal);
    const digest = (value: unknown) => typeof value === 'string' && /^[0-9a-f]{64}$/.test(value);
    if (value.operation !== 'proof_execute' || typeof value.job_id !== 'string' || !/^proof-[0-9a-f]{64}$/.test(value.job_id)
      || (job !== undefined && value.job_id !== job)
      || ![value.receipt_storage_key, value.receipt_digest, value.scope_digest, value.coordination_request_digest].every(digest)
      || !['not_attempted', 'unknown', 'durable_execution_recorded'].includes(value.execution_status)
      || (value.state === 'attempt_started' ? value.execution_status === 'not_attempted' : value.execution_status !== 'not_attempted')
      || (value.execution_status === 'durable_execution_recorded' ? typeof value.execution_operation_id !== 'string' || !value.execution_operation_id : value.execution_operation_id !== null)) {
      throw new WholepactError({ code: options ? 'EXTERNAL_OUTCOME_UNCERTAIN' : 'INVALID_RESPONSE', message: 'Exact proof execution response was not established. Preserve the original request and inspect the native host.', retryable: false, details: {idempotency_key: options?.idempotencyKey, agreement_id: agreement, job_id: job} });
    }
    return value;
  }
  /** Request cached status reconciliation only; the native owner must separately inspect the original encrypted job. */
  requestNativeProofReconciliation(agreementId: string, request: NativeProofReconcileRequest, options: MutationOptions): Promise<NativeProofRequestView> {
    resourceId(request.candidate_id); resourceId(request.job_id);
    if (options.expectedRevision === undefined) throw new Error('An exact agreement revision is required.');
    return this.mutate<NativeProofRequestView>(`/agreements/${resourceId(agreementId)}/native-proof-requests`, request, options)
      .then(value => this.nativeProofRequestResponse(value, agreementId, options, request.candidate_id, request.job_id));
  }
  nativeProofRequests(agreementId: string, signal?: AbortSignal): Promise<NativeProofRequestView[]> {
    return this.request<NativeProofRequestView[]>(`/agreements/${resourceId(agreementId)}/native-proof-requests`, { signal }).then(values => {
      if (!Array.isArray(values) || values.length > 16 || new Set(values.map(value => value?.request_id)).size !== values.length) {
        throw new WholepactError({code:'INVALID_RESPONSE',message:'Invalid retained proof request inventory.',retryable:false});
      }
      return values.map(value => this.nativeProofRequestResponse(value, agreementId));
    });
  }
  nativeProofRequest(agreementId: string, requestId: string, signal?: AbortSignal): Promise<NativeProofRequestView> {
    return this.request<NativeProofRequestView>(`/agreements/${resourceId(agreementId)}/native-proof-requests/${resourceId(requestId)}`, { signal }).then(value => {
      const checked = this.nativeProofRequestResponse(value, agreementId);
      if (checked.request_id !== requestId) throw new WholepactError({code:'INVALID_RESPONSE',message:'Retained proof request identity differs from the requested identity.',retryable:false});
      return checked;
    });
  }
  withdrawNativeProofRequest(agreementId: string, requestId: string, options: MutationOptions): Promise<NativeProofRequestView> {
    if (options.expectedRevision === undefined) throw new Error('An exact agreement revision is required.');
    return this.mutate<NativeProofRequestView>(`/agreements/${resourceId(agreementId)}/native-proof-requests/${resourceId(requestId)}/withdraw`, {}, options)
      .then(value => this.nativeProofRequestResponse(value, agreementId, options, undefined, undefined, requestId));
  }
  private nativeProofRequestResponse(value: NativeProofRequestView, agreement: string, options?: MutationOptions, candidate?: string, job?: string, withdrawal?: string): NativeProofRequestView {
    this.nativeRequestResponse(value, agreement, options, candidate, withdrawal);
    const digest = (value: unknown) => typeof value === 'string' && /^[0-9a-f]{64}$/.test(value);
    if (value.operation !== 'proof_reconcile' || typeof value.job_id !== 'string' || !/^proof-[0-9a-f]{64}$/.test(value.job_id)
      || (job !== undefined && value.job_id !== job)
      || ![value.receipt_storage_key, value.receipt_digest, value.scope_digest, value.coordination_request_digest].every(digest)
      || !['not_attempted', 'unknown', 'cached_reconciliation_recorded'].includes(value.reconciliation_status)
      || (value.state === 'attempt_started' ? value.reconciliation_status === 'not_attempted' : value.reconciliation_status !== 'not_attempted')
      || (value.reconciliation_status === 'cached_reconciliation_recorded' ? typeof value.reconciliation_operation_id !== 'string' || !value.reconciliation_operation_id : value.reconciliation_operation_id !== null)) {
      throw new WholepactError({ code: options ? 'EXTERNAL_OUTCOME_UNCERTAIN' : 'INVALID_RESPONSE', message: 'Exact proof reconciliation response was not established. Preserve the original request and inspect the native host.', retryable: false, details: {idempotency_key: options?.idempotencyKey, agreement_id: agreement, job_id: job} });
    }
    return value;
  }
  private nativeRequestResponse(value: NativeRequestView, agreement: string, options?: MutationOptions, candidate?: string, withdrawal?: string): NativeRequestView {
    if (!value || Array.isArray(value) || value.schema_version !== 1 || value.agreement_id !== agreement
      || typeof value.request_id !== 'string' || !/^[0-9a-f]{64}$/.test(value.request_id)
      || typeof value.candidate_id !== 'string' || typeof value.manifest_digest !== 'string'
      || value.authorization_allowed !== false || value.result_status !== 'unknown_not_financial_evidence'
      || !['queued', 'withdrawn', 'attempt_started'].includes(value.state)
      || !Number.isSafeInteger(value.original_revision) || value.original_revision < 1
      || value.queued_revision !== value.original_revision + 1
      || (value.state === 'attempt_started' ? value.attempt_revision !== value.queued_revision + 1 : value.attempt_revision !== null)
      || (candidate !== undefined && (value.candidate_id !== candidate || value.original_revision !== options?.expectedRevision))
      || (withdrawal !== undefined && (value.request_id !== withdrawal || value.state !== 'withdrawn'))) {
      throw new WholepactError({ code: options ? 'EXTERNAL_OUTCOME_UNCERTAIN' : 'INVALID_RESPONSE', message: 'Native request response is incompatible. Preserve the exact original key and inspect retained requests; do not create a replacement.', retryable: false, details: { idempotency_key: options?.idempotencyKey, agreement_id: agreement, expected_revision: options?.expectedRevision } });
    }
    return value;
  }
  candidateProofJobs(id: string, signal?: AbortSignal): Promise<CandidateProofJobs> { return this.request(`/candidates/${resourceId(id)}/proof-jobs`, { signal }); }
  createProposal(id: string, options: MutationOptions): Promise<AgreementView> { return this.mutate(`/agreements/${resourceId(id)}/proposals`, {}, options); }
  proposal(id: string, signal?: AbortSignal): Promise<ProposalPreview> { return this.request(`/proposals/${resourceId(id)}`, { signal }); }
  reviewProposal(id: string, options: MutationOptions): Promise<AgreementView> { return this.mutate(`/proposals/${resourceId(id)}/verify`, {}, options); }
  recovery(signal?: AbortSignal): Promise<RecoveryStatus> { return this.request('/recovery', { signal }); }
  reviewCandidate(id: string, options: MutationOptions): Promise<AgreementView> { return this.mutate(`/candidates/${resourceId(id)}/verify`, {}, options); }
  requestCancellation(id: string, options: MutationOptions): Promise<AgreementView> { return this.mutate(`/agreements/${resourceId(id)}/cancellation-requests`, {}, options); }
  reconcile(id: string, options: MutationOptions): Promise<Operation> { return this.mutate(`/agreements/${resourceId(id)}/reconcile`, {}, options); }
  authorizations(signal?: AbortSignal): Promise<AuthorizationRecord[]> { return this.request('/authorizations', { signal }); }
  accounts(signal?: AbortSignal): Promise<AccountRecord[]> { return this.request('/accounts', { signal }); }
  records(signal?: AbortSignal): Promise<ParticipantRecordStatus> { return this.request('/records', { signal }); }
  operation(id: string, signal?: AbortSignal): Promise<Operation> { return this.request(`/operations/${resourceId(id)}`, { signal }); }
  mutate<T>(path: string, body: unknown, options: MutationOptions): Promise<T> {
    this.checkMutationOptions(options);
    return this.request(path, { method: 'POST', body, signal: options.signal, idempotencyKey: options.idempotencyKey, expectedRevision: options.expectedRevision });
  }
  private checkMutationOptions(options: MutationOptions): void {
    if (!/^[\x21-\x7e]{16,128}$/.test(options.idempotencyKey)) throw new Error('An idempotency key must have 16–128 printable non-space ASCII characters.');
    if (options.expectedRevision !== undefined && (!Number.isSafeInteger(options.expectedRevision) || options.expectedRevision < 0)) throw new Error('Expected revision must be a nonnegative safe integer.');
  }
  async request<T>(path: string, options: { method?: string; body?: unknown; jsonSource?: string; signal?: AbortSignal; idempotencyKey?: string; expectedRevision?: number; readOnly?: boolean } = {}): Promise<T> {
    if (!/^\/[a-zA-Z0-9/_:.-]+$/.test(path) || path.split('/').some(segment => segment === '.' || segment === '..')) throw new Error('Invalid API resource path.');
    if (options.jsonSource !== undefined && options.body !== undefined) throw new Error('Supply either typed JSON or original JSON source.');
    const mutation = options.method === 'POST' && !options.readOnly;
    const requestId = crypto.randomUUID();
    const headers = this.headers(requestId);
    if (options.method === 'POST') {
      headers.set('Content-Type', 'application/json');
      if (!this.#csrf) throw new Error('Connect to the local service before sending commands.');
      headers.set('X-Wholepact-CSRF', this.#csrf);
      if (options.idempotencyKey) headers.set('Idempotency-Key', options.idempotencyKey);
      if (options.expectedRevision !== undefined) headers.set('If-Match', `"${options.expectedRevision}"`);
    }
    options.signal?.throwIfAborted();
    const requestBody = options.jsonSource ?? (options.body === undefined ? undefined : JSON.stringify(options.body));
    let response: Response;
    try {
      response = await this.#fetch(`${this.baseUrl}${path}`, { method: options.method ?? 'GET', headers, body: requestBody, signal: options.signal, cache: 'no-store', credentials: 'omit', redirect: 'error', referrerPolicy: 'no-referrer' });
    } catch (error) {
      if (!mutation && error instanceof DOMException && error.name === 'AbortError') throw error;
      throw new WholepactError({ code: mutation ? 'EXTERNAL_OUTCOME_UNCERTAIN' : 'SERVICE_UNREACHABLE', message: mutation ? 'The service response was interrupted. Check the original operation before trying again; do not create a replacement payment.' : 'Cannot reach the local service. Check that it is running and permits this workspace origin.', retryable: !mutation, safe_actions: ['reconnect', 'inspect_original_operation'], details: { resource: path, idempotency_key: options.idempotencyKey, expected_revision: options.expectedRevision } }, 0, requestId);
    }
    const operationId = response.headers.get('x-operation-id');
    let body: unknown;
    try { body = response.status === 204 ? null : await response.json(); }
    catch {
      throw new WholepactError({ code: mutation ? 'EXTERNAL_OUTCOME_UNCERTAIN' : 'INVALID_RESPONSE', message: mutation ? 'The command response was incomplete. Inspect the original operation or retry the exact request with the same idempotency key.' : 'The service returned an incomplete or invalid response.', retryable: false, operation_id: operationId, safe_actions: ['inspect_original_operation'], details: { resource: path, idempotency_key: options.idempotencyKey, expected_revision: options.expectedRevision } }, response.status, requestId);
    }
    if (response.ok && response.status !== 204 && (body === null || typeof body !== 'object')) throw new WholepactError({ code: mutation ? 'EXTERNAL_OUTCOME_UNCERTAIN' : 'INVALID_RESPONSE', message: 'The local service returned an invalid response shape.', retryable: false, operation_id: operationId, details: { resource: path, idempotency_key: options.idempotencyKey } }, response.status, requestId);
    if (!response.ok) throw this.toError(body, response.status, requestId);
    return body as T;
  }
  /** Fetch-streamed SSE permits authorization headers. Consumers persist only event cursors. */
  async *events(after = 0, signal?: AbortSignal): AsyncGenerator<WholepactEvent> {
    if (!Number.isSafeInteger(after) || after < 0) throw new Error('Invalid event cursor.');
    const requestId = crypto.randomUUID(); const headers = this.headers(requestId); headers.set('Accept', 'text/event-stream');
    const response = await this.#fetch(`${this.baseUrl}/events?after=${after}`, { headers, signal, cache: 'no-store', credentials: 'omit', redirect: 'error', referrerPolicy: 'no-referrer' });
    if (!response.ok) throw this.toError(await response.json().catch(() => null), response.status, requestId);
    if (!response.body) throw new Error('The service returned no event stream.');
    const reader = response.body.getReader(); const decoder = new TextDecoder(); let pending = ''; let cursor = after;
    try {
      while (true) {
        const chunk = await reader.read(); if (chunk.done) break;
        pending += decoder.decode(chunk.value, { stream: true });
        pending = pending.replace(/\r\n/g, '\n');
        if (pending.length > 1_048_576) throw new Error('Event stream exceeded the bounded frame size.');
        let separator: number;
        while ((separator = pending.indexOf('\n\n')) !== -1) {
          const frame = pending.slice(0, separator); pending = pending.slice(separator + 2);
          const data = frame.split('\n').filter(line => line.startsWith('data:')).map(line => line.slice(5).trimStart()).join('\n');
          if (!data) continue;
          const eventType = frame.split('\n').find(line => line.startsWith('event:'))?.slice(6).trim();
          if (eventType === 'session_expired') throw new WholepactError({ code: 'AUTHENTICATION_REQUIRED', message: 'The event-stream session expired. Reconnect before relying on new observations.', retryable: false, safe_actions: ['reconnect'] }, 401, requestId);
          if (eventType === 'service_unavailable') throw new WholepactError({ code: 'STORAGE_UNAVAILABLE', message: 'The service stopped reading the durable event journal. Previously read observations may be stale.', retryable: true, safe_actions: ['reconnect'] }, 503, requestId);
          if (eventType && eventType !== 'wholepact') throw new Error('Unsupported service event type.');
          const event = JSON.parse(data) as WholepactEvent;
          if (!Number.isSafeInteger(event.sequence) || typeof event.event_id !== 'string' || typeof event.kind !== 'string') throw new Error('Malformed service event.');
          if (event.sequence <= cursor) continue;
          cursor = event.sequence; yield event;
        }
      }
    } finally { await reader.cancel().catch(() => {}); reader.releaseLock(); }
  }
  private headers(requestId: string): Headers {
    if (!this.#token) throw new Error('Session is disconnected.');
    return new Headers({ Authorization: `Bearer ${this.#token}`, Accept: 'application/json', 'X-Request-ID': requestId });
  }
  private toError(body: unknown, status: number, requestId: string): WholepactError {
    const value = (body && typeof body === 'object' && 'error' in body ? (body as { error: unknown }).error : body) as Partial<ApiErrorBody> | null;
    return new WholepactError({ code: value?.code ?? `HTTP_${status}`, message: value?.message ?? 'The local service could not complete this request.', retryable: value?.retryable ?? false, operation_id: value?.operation_id, safe_actions: value?.safe_actions, details: value?.details }, status, requestId);
  }
}

/** IDs are path segments, never URLs. Preserve the engine's scoped colon IDs. */
function resourceId(id: string): string {
  if (!/^[A-Za-z0-9_.:\-]{1,128}$/.test(id) || id === '.' || id === '..') throw new Error('Invalid API resource identifier.');
  return id;
}

/** Comparison only; service canonicalization and core validation remain authoritative. */
function canonicalJson(value: unknown): string {
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(',')}]`;
  if (value !== null && typeof value === 'object') return `{${Object.entries(value).sort(([a], [b]) => a.localeCompare(b)).map(([key, entry]) => `${JSON.stringify(key)}:${canonicalJson(entry)}`).join(',')}}`;
  return JSON.stringify(value);
}
