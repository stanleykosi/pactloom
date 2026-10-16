import type { NativeRequestView } from '@wholepact/sdk';
/** Reject unfamiliar or approval-shaped metadata rather than infer success. */
export function nativeRequestMetadata(value: unknown, agreement: string): NativeRequestView[] {
  if (!Array.isArray(value) || value.length > 16) throw new Error('Invalid native request inventory.');
  for (const item of value) {
    if (!item || typeof item !== 'object' || item.schema_version !== 1 || item.agreement_id !== agreement
      || item.authorization_allowed !== false || item.result_status !== 'unknown_not_financial_evidence'
      || !['queued', 'withdrawn', 'attempt_started'].includes(item.state)
      || typeof item.request_id !== 'string' || !/^[0-9a-f]{64}$/.test(item.request_id)
      || typeof item.candidate_id !== 'string' || typeof item.manifest_digest !== 'string'
      || !Number.isSafeInteger(item.original_revision) || item.original_revision < 1
      || item.queued_revision !== item.original_revision + 1
      || (item.state === 'attempt_started' ? item.attempt_revision !== item.queued_revision + 1 : item.attempt_revision !== null)) {
      throw new Error('Unrecognized native request metadata; inspect the native host.');
    }
  }
  if (new Set(value.map(item => item.request_id)).size !== value.length) throw new Error('Duplicate native request identity.');
  return value as NativeRequestView[];
}
export function canRequestNativeConstruction(requests: NativeRequestView[] | null, candidate: string,
  allowed: boolean, busy: boolean, uncertain: boolean): boolean {
  return allowed && !busy && !uncertain && requests !== null
    && !requests.some(item => item.candidate_id === candidate && item.state !== 'withdrawn');
}
