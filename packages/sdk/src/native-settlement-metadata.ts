import type { NativeSettlementRequestView, NativeSignedObservation } from './types.js';

const digest = (value: unknown): value is string => typeof value === 'string' && /^[0-9a-f]{64}$/.test(value);
const record = (value: unknown): value is Record<string, unknown> => value !== null && typeof value === 'object' && !Array.isArray(value);
const exactKeys = (value: Record<string, unknown>, keys: readonly string[]): boolean =>
  Object.keys(value).length === keys.length && keys.every(key => Object.hasOwn(value, key));
const signedKeys = ['result_id', 'request_digest', 'signed_candidate_digest', 'signatures_complete'] as const;
function signed(value: unknown): value is NativeSignedObservation {
  return record(value) && exactKeys(value, signedKeys)
    && typeof value.result_id === 'string' && /^signed-[0-9a-f]{64}$/.test(value.result_id)
    && digest(value.request_digest) && digest(value.signed_candidate_digest)
    && typeof value.signatures_complete === 'boolean';
}
const viewKeys = [
  'schema_version', 'operation', 'request_id', 'agreement_id', 'candidate_id', 'manifest_digest',
  'original_revision', 'queued_revision', 'attempt_revision', 'state', 'authorization_allowed',
  'result_status', 'kind', 'intake_request_id', 'job_id', 'signature_retention_key', 'proved_artifact_digest',
  'receipt_storage_key', 'receipt_digest', 'scope_digest', 'coordination_request_digest', 'observation', 'outcome_status',
] as const;

/** Parse historical display metadata only. It grants no consent or execution authority. */
export function nativeSettlementRequestMetadata(value: unknown, agreement: string): NativeSettlementRequestView[] {
  if (!Array.isArray(value) || value.length > 16) throw new Error('Invalid retained settlement request inventory.');
  const entries: NativeSettlementRequestView[] = [];
  for (const item of value) {
    if (!record(item) || !exactKeys(item, viewKeys) || item.schema_version !== 1
      || item.operation !== 'settlement_handoff' || item.agreement_id !== agreement
      || !digest(item.request_id) || !digest(item.intake_request_id) || !digest(item.manifest_digest)
      || typeof item.candidate_id !== 'string' || !/^[A-Za-z0-9_.:\-]{1,128}$/.test(item.candidate_id)
      || item.candidate_id === '.' || item.candidate_id === '..'
      || typeof item.job_id !== 'string' || !/^proof-[0-9a-f]{64}$/.test(item.job_id)
      || item.signature_retention_key !== `native-artifact-handoff-${item.intake_request_id}`
      || ![item.proved_artifact_digest, item.receipt_storage_key, item.receipt_digest, item.scope_digest, item.coordination_request_digest].every(digest)
      || item.authorization_allowed !== false || item.result_status !== 'historical_metadata_only'
      || typeof item.kind !== 'string' || !['signature_reconcile', 'transaction_checkpoint'].includes(item.kind)
      || typeof item.state !== 'string' || !['queued', 'withdrawn', 'attempt_started'].includes(item.state)
      || typeof item.original_revision !== 'number' || !Number.isSafeInteger(item.original_revision) || item.original_revision < 1
      || !Number.isSafeInteger(item.queued_revision) || item.queued_revision !== item.original_revision + 1
      || (item.state === 'attempt_started'
        ? !Number.isSafeInteger(item.attempt_revision) || item.attempt_revision !== (item.queued_revision as number) + 1
        : item.attempt_revision !== null)) {
      throw new Error('Unrecognized exact settlement request metadata; inspect the original native journals.');
    }
    if (item.state !== 'attempt_started') {
      if (item.outcome_status !== 'not_attempted' || item.observation !== null) throw new Error('An unstarted settlement request cannot contain a historical result.');
    } else if (item.observation === null) {
      if (item.outcome_status !== 'attempted_outcome_unknown') throw new Error('A started request without retained evidence has an unknown durable effect.');
    } else {
      const observation = item.observation;
      if (item.outcome_status !== 'historical_result_recorded' || !record(observation)) throw new Error('Invalid historical settlement observation.');
      if (item.kind === 'signature_reconcile') {
        if (!exactKeys(observation, ['type', 'evidence']) || observation.type !== 'signed' || !signed(observation.evidence)) throw new Error('Invalid historical signed observation.');
      } else if (!exactKeys(observation, ['type', 'signed', 'checkpoint_id', 'transaction_digest', 'txid'])
        || observation.type !== 'transaction' || !signed(observation.signed) || !observation.signed.signatures_complete
        || typeof observation.checkpoint_id !== 'string' || !/^transaction-[0-9a-f]{64}$/.test(observation.checkpoint_id)
        || !digest(observation.transaction_digest) || !digest(observation.txid)) {
        throw new Error('Invalid historical transaction observation.');
      }
    }
    entries.push(item as unknown as NativeSettlementRequestView);
  }
  if (new Set(entries.map(item => item.request_id)).size !== entries.length) throw new Error('Duplicate settlement request identity.');
  return entries;
}
