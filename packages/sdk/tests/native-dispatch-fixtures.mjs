// Synthetic metadata only. No real transaction, signature, provider or journal is used.
export const agreement = 'synthetic-agreement-001';
export const transactionId = 'a'.repeat(64);
export const requestId = 'b'.repeat(64);
export const journalId = 'f'.repeat(64);
export const signed = () => ({ result_id: 'signed-' + '4'.repeat(64), request_digest: '5'.repeat(64), signed_candidate_digest: '6'.repeat(64), signatures_complete: true });
export const view = () => ({
 schema_version: 1, operation: 'submission_dispatch', request_id: requestId, agreement_id: agreement,
 transaction_request_id: transactionId, intake_request_id: 'c'.repeat(64), candidate_id: 'synthetic-candidate-001', manifest_digest: 'd'.repeat(64),
 original_revision: 10, queued_revision: 11, attempt_revision: null, state: 'queued', authorization_allowed: false, result_status: 'historical_metadata_only',
 job_id: 'proof-' + 'e'.repeat(64), signature_retention_key: 'native-artifact-handoff-' + 'c'.repeat(64), proved_artifact_digest: '1'.repeat(64),
 receipt_storage_key: '2'.repeat(64), receipt_digest: '3'.repeat(64), scope_digest: '7'.repeat(64), coordination_request_digest: '8'.repeat(64),
 signed: signed(), checkpoint_id: 'transaction-' + '9'.repeat(64), transaction_digest: '0'.repeat(64), txid: 'a'.repeat(64),
 operation_id: `native-dispatch-${requestId}`, submission_journal_identity: null, observations: [], outcome_status: 'not_attempted',
});
export const started = () => ({ ...view(), state: 'attempt_started', attempt_revision: 12, submission_journal_identity: journalId, outcome_status: 'attempted_outcome_unknown' });
export const empty = () => ({ submission_journal_identity: journalId, descriptor: null, intent: null, attempts: [] });
export const descriptor = () => ({ operation_id: view().operation_id, obligation_id: 'synthetic-obligation-001', proposal_id: view().candidate_id,
 transaction_id: view().txid, bytes_sha256: view().transaction_digest, network: 'testnet', expiry_height: 3500000, consensus_branch_id: 0x77190ad9 });
export const snapshot = () => ({ ...empty(), descriptor: descriptor(), intent: { operation_id: view().operation_id, bytes_sha256: view().transaction_digest, historical_provider_state: 'submission_unknown' } });
export const attempt = (number = 1, outcome = { kind: 'unknown' }) => ({ number, source_id: 'synthetic-provider-001', started_at_unix_seconds: 1800000000 + number, outcome });
export const historical = (observations = [snapshot()]) => ({ ...started(), observations, outcome_status: 'historical_result_recorded' });
export const transaction = () => {
 const { transaction_request_id, operation_id, submission_journal_identity, observations, signed: evidence, checkpoint_id, transaction_digest, txid, ...common } = view();
 return { ...common, operation: 'settlement_handoff', request_id: transactionId, kind: 'transaction_checkpoint', state: 'attempt_started',
  original_revision: 7, queued_revision: 8, attempt_revision: 9, outcome_status: 'historical_result_recorded',
  observation: { type: 'transaction', signed: evidence, checkpoint_id, transaction_digest, txid } };
};
