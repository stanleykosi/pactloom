import { nativeDispatchRequestMetadata } from './native-dispatch-metadata.js';
import type { NativeDispatchObservation, NativeReconciliationRequest, NativeReconciliationRequestView, NativeHistoricalReconciliationReport } from './types.js';

const digest = (value: unknown): value is string => typeof value === 'string' && /^[0-9a-f]{64}$/.test(value);
const record = (value: unknown): value is Record<string, unknown> => value !== null && typeof value === 'object' && !Array.isArray(value);
const exactKeys = (value: Record<string, unknown>, keys: readonly string[]): boolean =>
  Object.keys(value).length === keys.length && keys.every(key => Object.hasOwn(value, key));
const integer = (value: unknown, maximum = Number.MAX_SAFE_INTEGER): value is number =>
  typeof value === 'number' && Number.isSafeInteger(value) && value >= 0 && value <= maximum;
const resource = (value: unknown): value is string => typeof value === 'string' && /^[A-Za-z0-9_.:\-]{1,128}$/.test(value) && value !== '.' && value !== '..';
const sourceId = (value: unknown): value is string => typeof value === 'string' && /^[A-Za-z0-9_.-]{1,128}$/.test(value);
const canonical = (value: unknown): string => JSON.stringify(value, (_key, item: unknown) =>
  record(item) ? Object.fromEntries(Object.keys(item).sort().map(key => [key, item[key]])) : item) ?? 'undefined';

/** Copy checked scalars before sending, so caller mutations cannot alter the original command binding. */
export function nativeReconciliationInput(value: unknown): NativeReconciliationRequest {
  if (!record(value) || !digest(value.dispatch_request_id)) throw new Error('Supply an exact original dispatch request ID and request kind.');
  if (value.kind === 'provider_observation' && exactKeys(value, ['kind', 'dispatch_request_id'])) {
    return { kind: value.kind, dispatch_request_id: value.dispatch_request_id };
  }
  if (value.kind === 'independent_record_resolution' && exactKeys(value, ['kind', 'dispatch_request_id', 'participant_id', 'record_id'])
    && resource(value.participant_id) && resource(value.record_id)) {
    return { kind: value.kind, dispatch_request_id: value.dispatch_request_id, participant_id: value.participant_id, record_id: value.record_id };
  }
  throw new Error('Supply only the original dispatch ID and request kind; independent resolution also requires exact existing participant and record IDs.');
}
const sourceKeys = ['transaction_request_id', 'intake_request_id', 'candidate_id', 'manifest_digest', 'job_id', 'signature_retention_key',
  'proved_artifact_digest', 'receipt_storage_key', 'receipt_digest', 'scope_digest', 'coordination_request_digest', 'signed',
  'checkpoint_id', 'transaction_digest', 'txid', 'operation_id', 'submission_journal_identity'] as const;
const viewKeys = ['schema_version', 'operation', 'kind', 'request_id', 'agreement_id', 'dispatch_request_id', ...sourceKeys,
  'original_revision', 'queued_revision', 'attempt_revision', 'state', 'authorization_allowed', 'result_status', 'outcome_status', 'observations', 'resolution_commit'] as const;

/** Reuse the dispatch parser only for immutable source/snapshot shape, not for historical dispatch revisions.
 * Reconciliation carries its own revision fence; the actual predecessor revision is checked against the inventory by the workspace/engine. */
function checkSubmission(item: Record<string, unknown>, observations: unknown[], agreement: string): void {
  const hasHistory = observations.some(value => record(value) && (value.descriptor !== null || value.intent !== null || Array.isArray(value.attempts) && value.attempts.length > 0));
  nativeDispatchRequestMetadata([{
    ...Object.fromEntries(sourceKeys.map(key => [key, item[key]])), schema_version: 1, operation: 'submission_dispatch',
    request_id: item.dispatch_request_id, agreement_id: agreement, original_revision: 1, queued_revision: 2, attempt_revision: 3,
    state: 'attempt_started', authorization_allowed: false, result_status: 'historical_metadata_only', observations,
    outcome_status: hasHistory ? 'historical_result_recorded' : 'attempted_outcome_unknown',
  }], agreement);
}
function block(value: unknown): boolean {
  return record(value) && exactKeys(value, ['height', 'hash']) && integer(value.height) && value.height > 0
    && typeof value.hash === 'string' && /^[0-9a-fA-F]{64}$/.test(value.hash) && !/^0+$/.test(value.hash);
}
const reportKeys = ['transaction_id', 'expiry_height', 'policy', 'observed_at_unix_seconds', 'valid_until_unix_seconds', 'state', 'last_inclusion',
  'confidence_lost', 'reorganization_observed', 'source_ids', 'source_tips', 'independently_consensus_verified', 'clears_authorization_exposure', 'permits_replacement'] as const;
function report(value: unknown, item: Record<string, unknown>, submission: NativeDispatchObservation): value is NativeHistoricalReconciliationReport {
  if (!record(value) || !exactKeys(value, reportKeys) || value.transaction_id !== item.txid
    || submission.descriptor === null || value.expiry_height !== submission.descriptor.expiry_height
    || !integer(value.expiry_height, 4294967295) || value.expiry_height === 0
    || !record(value.policy) || !exactKeys(value.policy, ['required_confirmations', 'expiry_observation_depth', 'sources'])
    || !integer(value.policy.required_confirmations, 100) || value.policy.required_confirmations === 0
    || !integer(value.policy.expiry_observation_depth, 100) || value.policy.expiry_observation_depth === 0
    || !Array.isArray(value.policy.sources) || value.policy.sources.length < 1 || value.policy.sources.length > 8
    || !value.policy.sources.every(sourceId) || new Set(value.policy.sources).size !== value.policy.sources.length
    || !integer(value.observed_at_unix_seconds) || !integer(value.valid_until_unix_seconds)
    || value.valid_until_unix_seconds < value.observed_at_unix_seconds
    || !record(value.state) || !exactKeys(value.state, ['status']) || value.state.status !== 'stale'
    || value.last_inclusion !== null && !block(value.last_inclusion)
    || typeof value.confidence_lost !== 'boolean' || typeof value.reorganization_observed !== 'boolean'
    || value.independently_consensus_verified !== false || value.clears_authorization_exposure !== false || value.permits_replacement !== false
    || !Array.isArray(value.source_ids) || value.source_ids.length > 8 || !value.source_ids.every(sourceId)
    || new Set(value.source_ids).size !== value.source_ids.length || !value.source_ids.every(id => (value.policy as { sources: unknown[] }).sources.includes(id))
    || !Array.isArray(value.source_tips) || value.source_tips.length > 8) return false;
  const tips = value.source_tips;
  if (!tips.every(tip => record(tip) && exactKeys(tip, ['source_id', 'tip']) && (value.source_ids as unknown[]).includes(tip.source_id) && block(tip.tip))) return false;
  return new Set(tips.map(tip => (tip as Record<string, unknown>).source_id)).size === tips.length;
}
function reportProgresses(previous: NativeHistoricalReconciliationReport | null, next: NativeHistoricalReconciliationReport | null): boolean {
  return previous === null || next !== null && next.transaction_id === previous.transaction_id && next.expiry_height === previous.expiry_height
    && canonical(next.policy) === canonical(previous.policy) && next.observed_at_unix_seconds >= previous.observed_at_unix_seconds
    && (previous.last_inclusion === null || next.last_inclusion !== null);
}

/** Bounded strict historical metadata only. A started request is never reset or upgraded to current settlement. */
export function nativeReconciliationRequestMetadata(value: unknown, agreement: string): NativeReconciliationRequestView[] {
  if (!resource(agreement) || !Array.isArray(value) || value.length > 16) throw new Error('Invalid retained reconciliation inventory.');
  const entries: NativeReconciliationRequestView[] = [];
  for (const item of value) {
    if (!record(item) || !exactKeys(item, item.kind === 'independent_record_resolution' ? [...viewKeys, 'participant_id', 'record_id'] : viewKeys)
      || item.schema_version !== 1 || item.operation !== 'settlement_reconciliation' || item.agreement_id !== agreement
      || !digest(item.request_id) || !digest(item.dispatch_request_id) || !digest(item.submission_journal_identity) || /^0+$/.test(item.submission_journal_identity)
      || item.authorization_allowed !== false || item.result_status !== 'historical_metadata_only'
      || !integer(item.original_revision) || item.original_revision < 1 || !integer(item.queued_revision) || item.queued_revision !== item.original_revision + 1
      || typeof item.state !== 'string' || !['queued', 'withdrawn', 'attempt_started'].includes(item.state)
      || (item.state === 'attempt_started' ? !integer(item.attempt_revision) || item.attempt_revision !== item.queued_revision + 1 : item.attempt_revision !== null)
      || !Array.isArray(item.observations) || item.observations.length > 16) throw new Error('Unrecognized exact reconciliation metadata. Preserve all original native journals.');
    nativeReconciliationInput(item.kind === 'independent_record_resolution'
      ? { kind: item.kind, dispatch_request_id: item.dispatch_request_id, participant_id: item.participant_id, record_id: item.record_id }
      : { kind: item.kind, dispatch_request_id: item.dispatch_request_id });
    checkSubmission(item, [], agreement);
    if (item.state !== 'attempt_started') {
      if (item.observations.length !== 0 || item.resolution_commit !== null || item.outcome_status !== 'not_attempted') throw new Error('Never-started requests cannot contain reconciliation results.');
    } else {
      let previous: NativeReconciliationRequestView['observations'][number] | undefined;
      const seen = new Set<string>();
      for (const value of item.observations) {
        if (!record(value) || !exactKeys(value, ['submission', 'report'])) throw new Error('Unrecognized reconciliation snapshot.');
        checkSubmission(item, [value.submission], agreement);
        const submission = value.submission as NativeDispatchObservation;
        if (value.report !== null && !report(value.report, item, submission)) throw new Error('Invalid historical provider report.');
        const snapshot = value as unknown as NativeReconciliationRequestView['observations'][number];
        if (previous !== undefined) {
          if (canonical(previous.submission) !== canonical(submission)) checkSubmission(item, [previous.submission, submission], agreement);
          if (!reportProgresses(previous.report, snapshot.report)) throw new Error('Regressed original reconciliation history.');
        }
        const fingerprint = canonical(snapshot);
        if (seen.has(fingerprint)) throw new Error('Duplicate historical reconciliation snapshot.');
        seen.add(fingerprint); previous = snapshot;
      }
      if (item.resolution_commit !== null && (item.kind !== 'independent_record_resolution' || !record(item.resolution_commit)
        || !exactKeys(item.resolution_commit, ['status', 'observation_stale'])
        || item.resolution_commit.status !== 'historically_applied_independent_resolution' || item.resolution_commit.observation_stale !== true)) throw new Error('Invalid historical independent resolution metadata.');
      const expected = item.resolution_commit !== null ? 'historical_resolution_commit_recorded'
        : item.kind === 'provider_observation' && item.observations.some(value => (value as { report: unknown }).report !== null)
          ? 'historical_observation_recorded' : 'attempted_outcome_unknown';
      if (item.outcome_status !== expected) throw new Error('Provider history cannot establish independent positive settlement or clear uncertainty.');
    }
    entries.push(item as unknown as NativeReconciliationRequestView);
  }
  const identities = new Set<string>(); const queued = new Set<string>();
  for (const item of entries) {
    if (identities.has(item.request_id)) throw new Error('Duplicate reconciliation request identity.');
    identities.add(item.request_id);
    const target = canonical(item.kind === 'provider_observation' ? [item.kind, item.dispatch_request_id] : [item.kind, item.dispatch_request_id, item.record_id]);
    if (item.state === 'queued') {
      if (queued.has(target)) throw new Error('Duplicate queued reconciliation target.');
      queued.add(target);
    }
    if (item.kind === 'independent_record_resolution' && entries.some(previous => previous.kind === 'independent_record_resolution'
      && previous.dispatch_request_id === item.dispatch_request_id && previous.record_id === item.record_id
      && previous.participant_id !== item.participant_id)) throw new Error('Conflicting participant for the exact original private record.');
    const original = entries.find(previous => previous.dispatch_request_id === item.dispatch_request_id);
    if (original && sourceKeys.some(key => canonical(original[key]) !== canonical(item[key]))) throw new Error('Conflicting retained original dispatch identity.');
  }
  return entries;
}
