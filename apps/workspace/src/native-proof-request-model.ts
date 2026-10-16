import type { NativeProofRequestView } from '@wholepact/sdk';
import { nativeRequestMetadata } from './native-request-model.ts';
export function nativeProofRequestMetadata(value: unknown, agreement: string): NativeProofRequestView[] {
  const entries = nativeRequestMetadata(value, agreement) as NativeProofRequestView[];
  const digest = (value: unknown) => typeof value === 'string' && /^[0-9a-f]{64}$/.test(value);
  for (const item of entries) {
    if (item.operation !== 'proof_reconcile' || typeof item.job_id !== 'string' || !/^proof-[0-9a-f]{64}$/.test(item.job_id)
      || ![item.receipt_storage_key,item.receipt_digest,item.scope_digest,item.coordination_request_digest].every(digest)
      || !['not_attempted','unknown','cached_reconciliation_recorded'].includes(item.reconciliation_status)
      || (item.state === 'attempt_started' ? item.reconciliation_status === 'not_attempted' : item.reconciliation_status !== 'not_attempted')
      || (item.reconciliation_status === 'cached_reconciliation_recorded' ? typeof item.reconciliation_operation_id !== 'string' || !item.reconciliation_operation_id : item.reconciliation_operation_id !== null)) {
      throw new Error('Unrecognized proof-reconciliation metadata; inspect the original native job.');
    }
  }
  return entries;
}
export function canRequestProofReconciliation(requests: NativeProofRequestView[] | null, candidate: string, job: string, allowed: boolean, busy: boolean, uncertain: boolean): boolean {
  return allowed && !busy && !uncertain && requests !== null && candidate.length > 0
    && /^proof-[0-9a-f]{64}$/.test(job)
    && !requests.some(item => item.candidate_id === candidate && item.job_id === job
      && item.state !== 'withdrawn' && item.reconciliation_status !== 'cached_reconciliation_recorded');
}
