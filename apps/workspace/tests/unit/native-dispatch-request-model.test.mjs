import { test } from 'node:test';
import assert from 'node:assert/strict';
import { nativeDispatchRequestMetadata, originalDispatchTransaction, sameDispatchOriginal, validateDispatchOriginals, canRequestNativeDispatch, dispatchAttemptLabel } from '../../src/native-dispatch-request-model.ts';
import { agreement, transactionId, view, started, empty, snapshot, attempt, historical, transaction } from '../../../../packages/sdk/tests/native-dispatch-fixtures.mjs';
const can = (requests, transactions = [transaction()], allowed = true, busy = false, uncertain = false) => canRequestNativeDispatch(requests, transactions, transactionId, allowed, busy, uncertain);

test('only a unique original attempted transaction request with complete historical evidence is eligible', () => {
 assert.equal(originalDispatchTransaction([transaction()], transactionId)?.request_id, transactionId);
 assert.equal(can([]), true);
 for (const patch of [
  { kind: 'signature_reconcile' }, { request_id: '0'.repeat(64) }, { state: 'queued' }, { state: 'withdrawn' },
  { outcome_status: 'attempted_outcome_unknown' }, { observation: null },
  { observation: { type: 'signed', evidence: transaction().observation.signed } },
  { observation: { ...transaction().observation, signed: { ...transaction().observation.signed, signatures_complete: false } } },
 ]) assert.equal(can([], [{ ...transaction(), ...patch }]), false, JSON.stringify(patch));
 assert.equal(can([], [transaction(), transaction()]), false);
 assert.equal(can([], null), false); assert.equal(can([], []), false); assert.equal(can(null), false);
});
test('every original source, signature and transaction identity must agree before displaying dispatch inventory', () => {
 const original = originalDispatchTransaction([transaction()], transactionId);
 assert.equal(sameDispatchOriginal(view(), original), true);
 assert.doesNotThrow(() => validateDispatchOriginals([view()], [transaction()]));
 for (const field of ['transaction_request_id', 'agreement_id', 'intake_request_id', 'candidate_id', 'job_id', 'manifest_digest', 'signature_retention_key', 'proved_artifact_digest', 'receipt_storage_key', 'receipt_digest', 'scope_digest', 'coordination_request_digest', 'checkpoint_id', 'transaction_digest', 'txid']) {
  const wrong = { ...view(), [field]: 'different-original' };
  assert.equal(sameDispatchOriginal(wrong, original), false, field);
  assert.throws(() => validateDispatchOriginals([wrong], [transaction()]), field);
 }
 for (const field of ['result_id', 'request_digest', 'signed_candidate_digest', 'signatures_complete']) {
  const wrong = { ...view(), signed: { ...view().signed, [field]: field === 'signatures_complete' ? false : 'different-original' } };
  assert.equal(sameDispatchOriginal(wrong, original), false, field);
 }
 assert.equal(sameDispatchOriginal({ ...view(), original_revision: 8 }, original), false);
 assert.throws(() => validateDispatchOriginals([view()], []));
 assert.throws(() => validateDispatchOriginals([view()], [transaction(), transaction()]));
 assert.equal(can([{ ...view(), manifest_digest: 'different-original' }]), false);
});
test('queued or started dispatch blocks replacement; only a never-started withdrawn request can be superseded', () => {
 for (const current of [view(), started(), historical(), { ...started(), observations: [empty()] }]) assert.equal(can([current]), false);
 assert.equal(can([{ ...view(), state: 'withdrawn' }]), true);
 const replacement = { ...view(), request_id: '1'.repeat(64), operation_id: 'native-dispatch-' + '1'.repeat(64) };
 assert.doesNotThrow(() => nativeDispatchRequestMetadata([{ ...view(), state: 'withdrawn' }, replacement], agreement));
 assert.throws(() => nativeDispatchRequestMetadata([view(), replacement], agreement));
});
test('missing grants, stale inventory, pending work and uncertainty keep dispatch disabled', () => {
 assert.equal(can([], [transaction()], false), false);
 assert.equal(can([], [transaction()], true, true), false);
 assert.equal(can([], [transaction()], true, false, true), false);
 assert.equal(can(null, [transaction()], true), false);
});
test('latest per-attempt uncertainty is never hidden by an earlier provider acknowledgement', () => {
 const prior = { ...snapshot(), intent: { ...snapshot().intent, historical_provider_state: 'backend_acknowledged' }, attempts: [attempt(1, { kind: 'acknowledged' })] };
 const current = { ...prior, attempts: [...prior.attempts, attempt(2)] };
 const checked = nativeDispatchRequestMetadata([historical([prior, current])], agreement)[0];
 const latest = checked.observations.at(-1);
 assert.equal(latest.intent.historical_provider_state, 'backend_acknowledged');
 assert.match(dispatchAttemptLabel(latest.attempts.at(-1).outcome), /Unknown; delivery may have occurred/);
 assert.match(dispatchAttemptLabel({ kind: 'acknowledged' }), /current settlement is unknown/);
 assert.match(dispatchAttemptLabel({ kind: 'rejected', code: -26 }), /other delivery remains possible/);
 assert.match(dispatchAttemptLabel({ kind: 'blocked_before_dispatch' }), /earlier delivery remains possible/);
 assert.match(dispatchAttemptLabel({ kind: 'indeterminate', reason: { code: 'timeout' } }), /delivery may have occurred/);
 assert.match(dispatchAttemptLabel({ kind: 'indeterminate', reason: { code: 'backend', grpc_code: 14 } }), /backend 14/);
});
test('empty status snapshots and all provider reports remain historical metadata without financial authority', () => {
 const unknown = nativeDispatchRequestMetadata([{ ...started(), observations: [empty()] }], agreement)[0];
 assert.equal(unknown.outcome_status, 'attempted_outcome_unknown');
 assert.equal(unknown.authorization_allowed, false);
 for (const patch of [{ authorization_allowed: true }, { result_status: 'settled' }, { retry_allowed: true }, { current_confirmations: 10 }, { outcome_status: 'payment_complete' }]) assert.throws(() => nativeDispatchRequestMetadata([{ ...historical(), ...patch }], agreement));
});
