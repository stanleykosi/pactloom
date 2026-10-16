import type { NativeArtifactHandoffRequestView, NativeSettlementRequestKind, NativeSettlementRequestView } from '@wholepact/sdk';
export { nativeSettlementRequestMetadata } from '@wholepact/sdk';

export function originalSettlementIntake(intakes: NativeArtifactHandoffRequestView[] | null, id: string): NativeArtifactHandoffRequestView | undefined {
  return intakes?.find(item => item.request_id === id && item.kind === 'signature_intake' && item.state === 'attempt_started');
}
function sameOriginal(item: NativeSettlementRequestView, intake: NativeArtifactHandoffRequestView): boolean {
  return item.intake_request_id === intake.request_id && item.agreement_id === intake.agreement_id
    && item.candidate_id === intake.candidate_id && item.job_id === intake.job_id
    && item.manifest_digest === intake.manifest_digest && item.proved_artifact_digest === intake.proved_artifact_digest
    && item.signature_retention_key === `native-artifact-handoff-${intake.request_id}`
    && item.receipt_storage_key === intake.receipt_storage_key && item.receipt_digest === intake.receipt_digest
    && item.scope_digest === intake.scope_digest && item.coordination_request_digest === intake.coordination_request_digest;
}
/** A matching historical signed result is a prerequisite, never current spending authority. */
export function hasOriginalSignedObservation(requests: NativeSettlementRequestView[], intake: NativeArtifactHandoffRequestView): boolean {
  const signed = requests.filter(item => item.kind === 'signature_reconcile' && sameOriginal(item, intake)
    && item.state === 'attempt_started' && item.outcome_status === 'historical_result_recorded'
    && item.observation?.type === 'signed' && item.observation.evidence.signatures_complete);
  if (signed.length === 0) return false;
  // Conflicting retained observations never authorize choosing whichever came first.
  const evidence = signed[0]?.observation;
  return signed.every(item => item.observation?.type === 'signed' && evidence?.type === 'signed'
    && item.observation.evidence.result_id === evidence.evidence.result_id
    && item.observation.evidence.request_digest === evidence.evidence.request_digest
    && item.observation.evidence.signed_candidate_digest === evidence.evidence.signed_candidate_digest);
}
export function canRequestNativeSettlement(
  requests: NativeSettlementRequestView[] | null, intakes: NativeArtifactHandoffRequestView[] | null,
  intakeId: string, kind: NativeSettlementRequestKind, allowed: boolean, busy: boolean, uncertain: boolean,
): boolean {
  const intake = originalSettlementIntake(intakes, intakeId);
  return allowed && !busy && !uncertain && requests !== null && intake !== undefined
    && ['signature_reconcile', 'transaction_checkpoint'].includes(kind)
    && !requests.some(item => item.intake_request_id === intakeId && item.kind === kind && item.state !== 'withdrawn')
    && (kind !== 'transaction_checkpoint' || hasOriginalSignedObservation(requests, intake));
}
