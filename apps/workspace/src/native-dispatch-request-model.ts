import type { NativeDispatchAttemptOutcome, NativeDispatchRequestView, NativeSettlementRequestView } from '@wholepact/sdk';
export { nativeDispatchRequestMetadata } from '@wholepact/sdk';

type TransactionRequest = NativeSettlementRequestView & {
  observation: Extract<NonNullable<NativeSettlementRequestView['observation']>, { type: 'transaction' }>;
};
/** Only a uniquely identified, attempted original with complete historical transaction evidence is eligible. */
export function originalDispatchTransaction(requests: NativeSettlementRequestView[] | null, id: string): TransactionRequest | undefined {
  const matches = requests?.filter(item => item.request_id === id);
  if (matches?.length !== 1) return undefined;
  const item = matches[0];
  return item?.kind === 'transaction_checkpoint' && item.state === 'attempt_started'
    && item.outcome_status === 'historical_result_recorded' && item.observation?.type === 'transaction'
    && item.observation.signed.signatures_complete === true ? item as TransactionRequest : undefined;
}
export function sameDispatchOriginal(item: NativeDispatchRequestView, transaction: TransactionRequest): boolean {
  const original = transaction.observation;
  return item.transaction_request_id === transaction.request_id && item.agreement_id === transaction.agreement_id
    && item.intake_request_id === transaction.intake_request_id && item.candidate_id === transaction.candidate_id
    && item.job_id === transaction.job_id && item.manifest_digest === transaction.manifest_digest
    && item.signature_retention_key === transaction.signature_retention_key
    && item.proved_artifact_digest === transaction.proved_artifact_digest
    && item.receipt_storage_key === transaction.receipt_storage_key && item.receipt_digest === transaction.receipt_digest
    && item.scope_digest === transaction.scope_digest && item.coordination_request_digest === transaction.coordination_request_digest
    && item.signed.result_id === original.signed.result_id && item.signed.request_digest === original.signed.request_digest
    && item.signed.signed_candidate_digest === original.signed.signed_candidate_digest
    && item.signed.signatures_complete === true && original.signed.signatures_complete === true
    && item.checkpoint_id === original.checkpoint_id && item.transaction_digest === original.transaction_digest && item.txid === original.txid
    && transaction.attempt_revision !== null && item.original_revision >= transaction.attempt_revision;
}
/** Incomplete or inconsistent original history disables the whole displayed inventory. */
export function validateDispatchOriginals(requests: NativeDispatchRequestView[], transactions: NativeSettlementRequestView[]): void {
  for (const item of requests) {
    const original = originalDispatchTransaction(transactions, item.transaction_request_id);
    if (!original || !sameDispatchOriginal(item, original)) throw new Error('Dispatch history does not match its exact original transaction request. Preserve the original journals and inspect the native host.');
  }
}
export function canRequestNativeDispatch(
  requests: NativeDispatchRequestView[] | null, transactions: NativeSettlementRequestView[] | null,
  transactionId: string, allowed: boolean, busy: boolean, uncertain: boolean,
): boolean {
  if (!allowed || busy || uncertain || requests === null || transactions === null) return false;
  try { validateDispatchOriginals(requests, transactions); } catch { return false; }
  return originalDispatchTransaction(transactions, transactionId) !== undefined
    && !requests.some(item => item.transaction_request_id === transactionId && item.state !== 'withdrawn');
}
/** Provider history never overrides the most recent attempt's separately reported uncertainty. */
export function dispatchAttemptLabel(outcome: NativeDispatchAttemptOutcome): string {
  switch (outcome.kind) {
    case 'unknown': return 'Unknown; delivery may have occurred';
    case 'acknowledged': return 'Provider acknowledgement recorded; current settlement is unknown';
    case 'rejected': return `Provider rejection ${outcome.code} recorded; other delivery remains possible`;
    case 'blocked_before_dispatch': return 'Blocked before this attempt dispatched; earlier delivery remains possible';
    case 'indeterminate': return `Indeterminate (${outcome.reason.code}${outcome.reason.code === 'backend' ? ` ${outcome.reason.grpc_code}` : ''}); delivery may have occurred`;
  }
}
