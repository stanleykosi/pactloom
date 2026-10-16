import type { NativeDispatchObservation, NativeDispatchRequestView, NativeDispatchAttemptOutcome, NativeSignedObservation } from './types.js';

const digest = (value: unknown): value is string => typeof value === 'string' && /^[0-9a-f]{64}$/.test(value);
const record = (value: unknown): value is Record<string, unknown> => value !== null && typeof value === 'object' && !Array.isArray(value);
const exactKeys = (value: Record<string, unknown>, keys: readonly string[]): boolean =>
  Object.keys(value).length === keys.length && keys.every(key => Object.hasOwn(value, key));
const integer = (value: unknown, maximum = Number.MAX_SAFE_INTEGER): value is number =>
  typeof value === 'number' && Number.isSafeInteger(value) && value >= 0 && value <= maximum;
const resource = (value: unknown): value is string => typeof value === 'string' && /^[A-Za-z0-9_.:\-]{1,128}$/.test(value) && value !== '.' && value !== '..';
const operationIdentity = (value: unknown): value is string => typeof value === 'string' && /^[\x21-\x7e]{16,128}$/.test(value);
const signedKeys = ['result_id', 'request_digest', 'signed_candidate_digest', 'signatures_complete'] as const;
function signed(value: unknown): value is NativeSignedObservation {
  return record(value) && exactKeys(value, signedKeys)
    && typeof value.result_id === 'string' && /^signed-[0-9a-f]{64}$/.test(value.result_id)
    && digest(value.request_digest) && digest(value.signed_candidate_digest) && value.signatures_complete === true;
}
function outcome(value: unknown): value is NativeDispatchAttemptOutcome {
  if (!record(value) || typeof value.kind !== 'string') return false;
  if (['unknown', 'acknowledged', 'blocked_before_dispatch'].includes(value.kind)) return exactKeys(value, ['kind']);
  if (value.kind === 'rejected') return exactKeys(value, ['kind', 'code']) && typeof value.code === 'number'
    && Number.isInteger(value.code) && value.code >= -2147483648 && value.code <= 2147483647 && value.code !== 0;
  if (value.kind !== 'indeterminate' || !exactKeys(value, ['kind', 'reason']) || !record(value.reason)) return false;
  const reason = value.reason;
  if (reason.code === 'backend') return exactKeys(reason, ['code', 'grpc_code']) && typeof reason.grpc_code === 'number'
    && Number.isInteger(reason.grpc_code) && reason.grpc_code >= -2147483648 && reason.grpc_code <= 2147483647;
  return exactKeys(reason, ['code']) && typeof reason.code === 'string'
    && ['timeout', 'interrupted', 'transport_unavailable', 'resource_limit', 'malformed_evidence', 'unsupported_capability', 'other'].includes(reason.code);
}
const descriptorKeys = ['operation_id', 'obligation_id', 'proposal_id', 'transaction_id', 'bytes_sha256', 'network', 'expiry_height', 'consensus_branch_id'] as const;
function observation(value: unknown, item: Record<string, unknown>): value is NativeDispatchObservation {
  if (!record(value) || !exactKeys(value, ['submission_journal_identity', 'descriptor', 'intent', 'attempts'])
    || value.submission_journal_identity !== item.submission_journal_identity || !Array.isArray(value.attempts) || value.attempts.length > 128) return false;
  if (value.descriptor !== null) {
    const d = value.descriptor;
    if (!record(d) || !exactKeys(d, descriptorKeys) || d.operation_id !== item.operation_id
      || !operationIdentity(d.obligation_id) || !operationIdentity(d.proposal_id) || d.proposal_id !== item.candidate_id
      || d.transaction_id !== item.txid || d.bytes_sha256 !== item.transaction_digest
      || d.network !== 'testnet' || !integer(d.expiry_height, 4294967295) || d.expiry_height === 0
      || d.consensus_branch_id !== 0x77190ad9) return false;
  }
  if (value.intent !== null) {
    const i = value.intent;
    if (!record(i) || !exactKeys(i, ['operation_id', 'bytes_sha256', 'historical_provider_state'])
      || i.operation_id !== item.operation_id || i.bytes_sha256 !== item.transaction_digest
      || typeof i.historical_provider_state !== 'string'
      || !['submission_unknown', 'backend_acknowledged', 'backend_rejected'].includes(i.historical_provider_state)) return false;
  }
  if ((value.descriptor === null) !== (value.intent === null) || value.descriptor === null && value.attempts.length !== 0) return false;
  let timestamp = 0;
  for (let index = 0; index < value.attempts.length; index++) {
    const a = value.attempts[index];
    if (!record(a) || !exactKeys(a, ['number', 'source_id', 'started_at_unix_seconds', 'outcome'])
      || a.number !== index + 1 || typeof a.source_id !== 'string' || !/^[A-Za-z0-9_.-]{1,128}$/.test(a.source_id)
      || !integer(a.started_at_unix_seconds) || a.started_at_unix_seconds < timestamp || !outcome(a.outcome)) return false;
    timestamp = a.started_at_unix_seconds;
  }
  return true;
}
function sameOutcome(old: NativeDispatchAttemptOutcome, next: NativeDispatchAttemptOutcome): boolean {
  if (old.kind !== next.kind) return false;
  if (old.kind === 'rejected' && next.kind === 'rejected') return old.code === next.code;
  if (old.kind === 'indeterminate' && next.kind === 'indeterminate') {
    return old.reason.code === next.reason.code && (old.reason.code !== 'backend'
      || next.reason.code === 'backend' && old.reason.grpc_code === next.reason.grpc_code);
  }
  return true;
}
/** Snapshots are append-only. A formerly unknown attempt may gain one final outcome. */
function monotone(old: NativeDispatchObservation, next: NativeDispatchObservation): boolean {
  if (old.submission_journal_identity !== next.submission_journal_identity || old.attempts.length > next.attempts.length) return false;
  if (old.descriptor !== null && (next.descriptor === null
    || descriptorKeys.some(key => old.descriptor?.[key] !== next.descriptor?.[key]))) return false;
  if (old.intent !== null) {
    if (next.intent === null || old.intent.operation_id !== next.intent.operation_id || old.intent.bytes_sha256 !== next.intent.bytes_sha256) return false;
    const ranks = { submission_unknown: 0, backend_rejected: 1, backend_acknowledged: 2 };
    if (ranks[next.intent.historical_provider_state] < ranks[old.intent.historical_provider_state]) return false;
  }
  return old.attempts.every((previous, index) => {
    const following = next.attempts[index];
    return following !== undefined && previous.number === following.number && previous.source_id === following.source_id
      && previous.started_at_unix_seconds === following.started_at_unix_seconds
      && (previous.outcome.kind === 'unknown' || sameOutcome(previous.outcome, following.outcome));
  });
}
const viewKeys = [
  'schema_version', 'operation', 'request_id', 'agreement_id', 'candidate_id', 'manifest_digest',
  'original_revision', 'queued_revision', 'attempt_revision', 'state', 'authorization_allowed', 'result_status',
  'transaction_request_id', 'intake_request_id', 'job_id', 'signature_retention_key', 'proved_artifact_digest',
  'receipt_storage_key', 'receipt_digest', 'scope_digest', 'coordination_request_digest', 'signed',
  'checkpoint_id', 'transaction_digest', 'txid', 'operation_id', 'submission_journal_identity', 'observations', 'outcome_status',
] as const;

/** Strict historical display metadata. No provider report establishes current settlement or retry authority. */
export function nativeDispatchRequestMetadata(value: unknown, agreement: string): NativeDispatchRequestView[] {
  if (!resource(agreement) || !Array.isArray(value) || value.length > 16) throw new Error('Invalid retained dispatch request inventory.');
  const entries: NativeDispatchRequestView[] = [];
  for (const item of value) {
    if (!record(item) || !exactKeys(item, viewKeys) || item.schema_version !== 1
      || item.operation !== 'submission_dispatch' || item.agreement_id !== agreement
      || ![item.request_id, item.transaction_request_id, item.intake_request_id, item.manifest_digest,
        item.proved_artifact_digest, item.receipt_storage_key, item.receipt_digest, item.scope_digest,
        item.coordination_request_digest, item.transaction_digest, item.txid].every(digest)
      || !resource(item.candidate_id) || typeof item.job_id !== 'string' || !/^proof-[0-9a-f]{64}$/.test(item.job_id)
      || item.signature_retention_key !== `native-artifact-handoff-${item.intake_request_id}` || !signed(item.signed)
      || typeof item.checkpoint_id !== 'string' || !/^transaction-[0-9a-f]{64}$/.test(item.checkpoint_id)
      || item.operation_id !== `native-dispatch-${item.request_id}` || item.authorization_allowed !== false
      || item.result_status !== 'historical_metadata_only' || typeof item.state !== 'string'
      || !['queued', 'withdrawn', 'attempt_started'].includes(item.state)
      || !integer(item.original_revision) || item.original_revision < 1
      || !integer(item.queued_revision) || item.queued_revision !== item.original_revision + 1
      || (item.state === 'attempt_started'
        ? !integer(item.attempt_revision) || item.attempt_revision !== item.queued_revision + 1
        : item.attempt_revision !== null)
      || !Array.isArray(item.observations) || item.observations.length > 16) {
      throw new Error('Unrecognized exact dispatch request metadata; preserve the original native journals.');
    }
    if (item.state !== 'attempt_started') {
      if (item.submission_journal_identity !== null || item.outcome_status !== 'not_attempted' || item.observations.length !== 0) {
        throw new Error('An unstarted dispatch request cannot contain submission history.');
      }
    } else {
      if (!digest(item.submission_journal_identity) || /^0+$/.test(item.submission_journal_identity)) {
        throw new Error('A started dispatch request must retain its original submission journal identity.');
      }
      let previous: NativeDispatchObservation | undefined;
      const seen: NativeDispatchObservation[] = [];
      for (const snapshot of item.observations) {
        if (!observation(snapshot, item) || previous !== undefined && !monotone(previous, snapshot)
          || seen.some(old => monotone(old, snapshot) && monotone(snapshot, old))) {
          throw new Error('Invalid, conflicting or regressed historical dispatch observations.');
        }
        previous = snapshot; seen.push(snapshot);
      }
      const hasHistory = item.observations.some(snapshot => snapshot.descriptor !== null || snapshot.intent !== null || snapshot.attempts.length !== 0);
      if (item.outcome_status !== (hasHistory ? 'historical_result_recorded' : 'attempted_outcome_unknown')) {
        throw new Error('An empty submission journal cannot establish that no dispatch occurred.');
      }
    }
    entries.push(item as unknown as NativeDispatchRequestView);
  }
  const sourceKeys = ['agreement_id', 'intake_request_id', 'candidate_id', 'manifest_digest', 'job_id', 'signature_retention_key',
    'proved_artifact_digest', 'receipt_storage_key', 'receipt_digest', 'scope_digest', 'coordination_request_digest',
    'checkpoint_id', 'transaction_digest', 'txid'] as const;
  for (const item of entries) {
    const original = entries.find(previous => previous.transaction_request_id === item.transaction_request_id);
    if (original && (sourceKeys.some(key => original[key] !== item[key])
      || signedKeys.some(key => original.signed[key] !== item.signed[key]))) throw new Error('Conflicting retained original transaction source.');
  }
  const active = entries.filter(item => item.state !== 'withdrawn');
  if (new Set(entries.map(item => item.request_id)).size !== entries.length
    || new Set(active.map(item => item.transaction_request_id)).size !== active.length) throw new Error('Duplicate dispatch request or active original transaction identity.');
  return entries;
}
