import { test } from 'node:test';
import assert from 'node:assert/strict';
import { nativeReconciliationRequestMetadata, originalReconciliationDispatch, sameReconciliationOriginal, validateReconciliationOriginals, sameReconciliationTarget, canRequestNativeReconciliation, reconciliationObservationLabel } from '../../src/native-reconciliation-request-model.ts';
import { agreement, dispatchId, dispatch, input, view, started, empty, snapshot, historical, resolved } from '../../../../packages/sdk/tests/native-reconciliation-fixtures.mjs';
const can = (requests, request = input(), originals = [dispatch()], allowed = true, busy = false, uncertain = false) => canRequestNativeReconciliation(requests, originals, request, allowed, busy, uncertain);

test('an exact uniquely retained started original remains eligible even with no provider or dispatch history', () => {
 assert.equal(originalReconciliationDispatch([dispatch()], dispatchId)?.request_id, dispatchId);
 assert.equal(can([]), true);
 for (const patch of [{ request_id: '0'.repeat(64) }, { state: 'queued' }, { state: 'withdrawn' }, { attempt_revision: null }, { submission_journal_identity: null }, { submission_journal_identity: '0'.repeat(64) }, { submission_journal_identity: 'F'.repeat(64) }]) assert.equal(can([], input(), [{ ...dispatch(), ...patch }]), false);
 assert.equal(can([], input(), [dispatch(), dispatch()]), false);
 assert.equal(can([], input(), null), false); assert.equal(can([], input(), []), false); assert.equal(can(null), false);
});
test('all flattened originals, signed identities and original revision must bind to retained dispatch', () => {
 assert.equal(sameReconciliationOriginal(view(), dispatch()), true);
 assert.doesNotThrow(() => validateReconciliationOriginals([view(), { ...resolved(), request_id: '1'.repeat(64) }], [dispatch()]));
 for (const field of ['dispatch_request_id', 'agreement_id', 'transaction_request_id', 'intake_request_id', 'candidate_id', 'manifest_digest', 'job_id', 'signature_retention_key', 'proved_artifact_digest', 'receipt_storage_key', 'receipt_digest', 'scope_digest', 'coordination_request_digest', 'checkpoint_id', 'transaction_digest', 'txid', 'operation_id', 'submission_journal_identity']) {
  const wrong = { ...view(), [field]: 'different-original' };
  assert.equal(sameReconciliationOriginal(wrong, dispatch()), false, field); assert.throws(() => validateReconciliationOriginals([wrong], [dispatch()]), field);
 }
 for (const field of ['result_id', 'request_digest', 'signed_candidate_digest', 'signatures_complete']) assert.equal(sameReconciliationOriginal({ ...view(), signed: { ...view().signed, [field]: field === 'signatures_complete' ? false : 'different' } }, dispatch()), false);
 assert.equal(sameReconciliationOriginal({ ...view(), original_revision: 11 }, dispatch()), false);
 assert.equal(can([{ ...view(), manifest_digest: 'different' }]), false);
 assert.throws(() => validateReconciliationOriginals([view()], []));
});
test('only a same-target queued request blocks a distinct new explicit review; started rows are never reset or removed', () => {
 assert.equal(can([view()]), false);
 for (const prior of [started(), historical(), historical([empty()]), { ...view(), state: 'withdrawn' }]) assert.equal(can([prior]), true);
 assert.equal(can([view()], input('independent_record_resolution')), true);
 assert.equal(can([view('independent_record_resolution')], input()), true);
 assert.equal(can([view('independent_record_resolution')], input('independent_record_resolution')), false);
 assert.equal(can([resolved()], input('independent_record_resolution')), true);
 assert.equal(can([view('independent_record_resolution')], { ...input('independent_record_resolution'), participant_id: 'other-participant' }), false);
 assert.equal(can([view('independent_record_resolution')], { ...input('independent_record_resolution'), record_id: 'other-record' }), true);
 assert.equal(sameReconciliationTarget(input(), input('independent_record_resolution')), false);
 const original = started(); const next = { ...view(), request_id: '1'.repeat(64), original_revision: 15, queued_revision: 16 };
 const checked = nativeReconciliationRequestMetadata([original, next], agreement);
 assert.equal(checked.length, 2); assert.equal(checked[0].state, 'attempt_started'); assert.equal(checked[0].outcome_status, 'attempted_outcome_unknown');
 assert.throws(() => nativeReconciliationRequestMetadata([view(), next], agreement));
});
test('missing grants, stale inventory, pending commands, invalid record selectors and uncertain acknowledgement block new requests', () => {
 assert.equal(can([], input(), [dispatch()], false), false);
 assert.equal(can([], input(), [dispatch()], true, true), false);
 assert.equal(can([], input(), [dispatch()], true, false, true), false);
 for (const field of ['participant_id', 'record_id']) for (const value of ['', '.', '..', 'https://source', 'x'.repeat(129)]) assert.equal(can([], { ...input('independent_record_resolution'), [field]: value }), false);
});
test('display labels separate provider history, historical independent application and current exposure', () => {
 assert.match(reconciliationObservationLabel(empty()), /outcome remains unknown/);
 assert.match(reconciliationObservationLabel(snapshot()), /stale on restore/);
 assert.match(reconciliationObservationLabel(snapshot()), /independent settlement and exposure clearance are not established/);
 assert.equal(nativeReconciliationRequestMetadata([historical([snapshot()], 'independent_record_resolution')], agreement)[0].outcome_status, 'attempted_outcome_unknown');
 const committed = nativeReconciliationRequestMetadata([resolved()], agreement)[0];
 assert.equal(committed.state, 'attempt_started'); assert.equal(committed.authorization_allowed, false); assert.equal(committed.resolution_commit.observation_stale, true);
});
