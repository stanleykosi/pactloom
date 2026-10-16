import type { NativeDispatchRequestView, NativeReconciliationRequest, NativeReconciliationRequestView, NativeReconciliationObservation } from '@wholepact/sdk';
export { nativeReconciliationRequestMetadata } from '@wholepact/sdk';

const reference = (value: unknown): value is string => typeof value === 'string' && /^[A-Za-z0-9_.:\-]{1,128}$/.test(value) && value !== '.' && value !== '..';
/** A started original is eligible even when its submission outcome and journal contents remain unknown. */
export function originalReconciliationDispatch(requests: NativeDispatchRequestView[] | null, id: string): NativeDispatchRequestView | undefined {
  const matches = requests?.filter(item => item.request_id === id);
  if (matches?.length !== 1) return undefined;
  const item = matches[0];
  return item?.state === 'attempt_started' && item.attempt_revision !== null
    && typeof item.submission_journal_identity === 'string' && /^[0-9a-f]{64}$/.test(item.submission_journal_identity)
    && !/^0+$/.test(item.submission_journal_identity) ? item : undefined;
}
const sourceKeys = ['agreement_id', 'transaction_request_id', 'intake_request_id', 'candidate_id', 'manifest_digest', 'job_id', 'signature_retention_key',
  'proved_artifact_digest', 'receipt_storage_key', 'receipt_digest', 'scope_digest', 'coordination_request_digest', 'checkpoint_id',
  'transaction_digest', 'txid', 'operation_id', 'submission_journal_identity'] as const;
const signedKeys = ['result_id', 'request_digest', 'signed_candidate_digest', 'signatures_complete'] as const;
export function sameReconciliationOriginal(item: NativeReconciliationRequestView, original: NativeDispatchRequestView): boolean {
  return item.dispatch_request_id === original.request_id && sourceKeys.every(key => item[key] === original[key])
    && signedKeys.every(key => item.signed[key] === original.signed[key])
    && original.attempt_revision !== null && item.original_revision >= original.attempt_revision;
}
export function validateReconciliationOriginals(requests: NativeReconciliationRequestView[], originals: NativeDispatchRequestView[]): void {
  for (const item of requests) {
    const original = originalReconciliationDispatch(originals, item.dispatch_request_id);
    if (!original || !sameReconciliationOriginal(item, original)) throw new Error('Reconciliation history does not match its exact original dispatch. Preserve all native journals and inspect the stopped native host.');
  }
}
export function sameReconciliationTarget(item: NativeReconciliationRequest, request: NativeReconciliationRequest): boolean {
  return item.kind === request.kind && item.dispatch_request_id === request.dispatch_request_id
    && (request.kind === 'provider_observation' || item.kind === 'independent_record_resolution'
      && item.record_id === request.record_id);
}
export function canRequestNativeReconciliation(
  requests: NativeReconciliationRequestView[] | null, originals: NativeDispatchRequestView[] | null,
  request: NativeReconciliationRequest, allowed: boolean, busy: boolean, uncertain: boolean,
): boolean {
  if (!allowed || busy || uncertain || requests === null || originals === null
    || !['provider_observation', 'independent_record_resolution'].includes(request.kind)
    || !originalReconciliationDispatch(originals, request.dispatch_request_id)) return false;
  if (request.kind === 'independent_record_resolution' && (!reference(request.participant_id) || !reference(request.record_id))) return false;
  try { validateReconciliationOriginals(requests, originals); } catch { return false; }
  return !requests.some(item => item.state === 'queued' && sameReconciliationTarget(item, request));
}
export function reconciliationObservationLabel(observation: NativeReconciliationObservation): string {
  return observation.report === null
    ? 'No provider report retained; the outcome remains unknown'
    : 'Historical provider observation, stale on restore; independent settlement and exposure clearance are not established';
}
