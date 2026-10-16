import type { NativeArtifactHandoffRequestView } from '@wholepact/sdk';
import { nativeRequestMetadata } from './native-request-model.ts';
export function nativeArtifactHandoffRequestMetadata(value: unknown, agreement: string): NativeArtifactHandoffRequestView[] {
  const entries = nativeRequestMetadata(value, agreement) as NativeArtifactHandoffRequestView[];
  const digest = (value: unknown) => typeof value === 'string' && /^[0-9a-f]{64}$/.test(value);
  for (const item of entries) {
    if (item.operation !== 'artifact_handoff' || typeof item.job_id !== 'string' || !/^proof-[0-9a-f]{64}$/.test(item.job_id)
      || !['signer_review','signature_intake'].includes(item.kind)
      || !digest(item.proved_artifact_digest)
      || ![item.receipt_storage_key,item.receipt_digest,item.scope_digest,item.coordination_request_digest].every(digest)
      || !['not_attempted','attempted_outcome_unknown'].includes(item.handoff_status)
      || (item.state === 'attempt_started' ? item.handoff_status === 'not_attempted' : item.handoff_status !== 'not_attempted')
) {
      throw new Error('Unrecognized proof-reconciliation metadata; inspect the original native job.');
    }
  }
  return entries;
}
export function canRequestArtifactHandoff(requests: NativeArtifactHandoffRequestView[] | null, candidate: string, job: string, kind: 'signer_review'|'signature_intake', allowed: boolean, busy: boolean, uncertain: boolean): boolean {
  return allowed && !busy && !uncertain && requests !== null && candidate.length > 0
    && /^proof-[0-9a-f]{64}$/.test(job)
    && !requests.some(item => item.candidate_id === candidate && item.job_id === job && item.kind === kind
      && item.state !== 'withdrawn');
}
