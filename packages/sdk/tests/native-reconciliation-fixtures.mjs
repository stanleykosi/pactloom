// Synthetic display metadata only. No transaction, signature, provider, node or private record is exercised.
import { agreement, requestId as dispatchId, journalId, started as dispatch, snapshot as submission, empty as emptySubmission } from './native-dispatch-fixtures.mjs';
export { agreement, dispatchId, journalId, dispatch, submission, emptySubmission };
export const requestId = 'e'.repeat(64);
export const input = (kind = 'provider_observation') => kind === 'provider_observation' ? { kind, dispatch_request_id: dispatchId }
 : { kind, dispatch_request_id: dispatchId, participant_id: 'synthetic-participant', record_id: 'synthetic-record' };
export const view = (kind = 'provider_observation') => ({ ...dispatch(), ...input(kind), operation: 'settlement_reconciliation', request_id: requestId,
 original_revision: 12, queued_revision: 13, attempt_revision: null, state: 'queued', observations: [], resolution_commit: null, outcome_status: 'not_attempted' });
export const started = (kind = 'provider_observation') => ({ ...view(kind), state: 'attempt_started', attempt_revision: 14, outcome_status: 'attempted_outcome_unknown' });
export const block = () => ({ height: 3499999, hash: 'a'.repeat(64) });
export const report = () => ({ transaction_id: dispatch().txid, expiry_height: submission().descriptor.expiry_height,
 policy: { required_confirmations: 10, expiry_observation_depth: 10, sources: ['synthetic-source'] },
 observed_at_unix_seconds: 1800000000, valid_until_unix_seconds: 1800000030, state: { status: 'stale' }, last_inclusion: block(),
 confidence_lost: true, reorganization_observed: false, source_ids: ['synthetic-source'], source_tips: [{ source_id: 'synthetic-source', tip: block() }],
 independently_consensus_verified: false, clears_authorization_exposure: false, permits_replacement: false });
export const empty = () => ({ submission: emptySubmission(), report: null });
export const snapshot = () => ({ submission: submission(), report: report() });
export const historical = (observations = [snapshot()], kind = 'provider_observation') => ({ ...started(kind), observations,
 outcome_status: kind === 'provider_observation' && observations.some(item => item.report !== null) ? 'historical_observation_recorded' : 'attempted_outcome_unknown' });
export const resolved = () => ({ ...historical([snapshot()], 'independent_record_resolution'), outcome_status: 'historical_resolution_commit_recorded',
 resolution_commit: { status: 'historically_applied_independent_resolution', observation_stale: true } });
