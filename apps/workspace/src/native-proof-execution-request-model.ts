import type { NativeProofExecutionRequestView } from '@wholepact/sdk';
import { nativeRequestMetadata } from './native-request-model.ts';
export function nativeProofExecutionRequestMetadata(value: unknown, agreement: string): NativeProofExecutionRequestView[] {
  const entries = nativeRequestMetadata(value, agreement) as NativeProofExecutionRequestView[];
  const digest = (value: unknown) => typeof value === 'string' && /^[0-9a-f]{64}$/.test(value);
  for (const item of entries) {
    if (item.operation !== 'proof_execute' || typeof item.job_id !== 'string' || !/^proof-[0-9a-f]{64}$/.test(item.job_id)
      || ![item.receipt_storage_key,item.receipt_digest,item.scope_digest,item.coordination_request_digest].every(digest)
      || !['not_attempted','unknown','durable_execution_recorded'].includes(item.execution_status)
      || (item.state === 'attempt_started' ? item.execution_status === 'not_attempted' : item.execution_status !== 'not_attempted')
      || (item.execution_status === 'durable_execution_recorded' ? typeof item.execution_operation_id !== 'string' || !item.execution_operation_id : item.execution_operation_id !== null)) {
      throw new Error('Unrecognized proof-reconciliation metadata; inspect the original native job.');
    }
  }
  return entries;
}
export function canRequestProofExecution(requests: NativeProofExecutionRequestView[] | null, candidate: string, job: string, allowed: boolean, busy: boolean, uncertain: boolean): boolean {
  return allowed && !busy && !uncertain && requests !== null && candidate.length > 0
    && /^proof-[0-9a-f]{64}$/.test(job)
    && !requests.some(item => item.candidate_id === candidate && item.job_id === job
      && item.state !== 'withdrawn');
}
