import { test } from 'node:test';
import assert from 'node:assert/strict';
import { WholepactClient, WholepactError, nativeReconciliationRequestMetadata } from '../dist/index.js';
import { agreement, dispatchId, requestId, input, view, started, empty, snapshot, report, historical, resolved } from './native-reconciliation-fixtures.mjs';
const session = { session_token: 'synthetic-session', csrf_token: 'synthetic-csrf' };
const json = value => new Response(JSON.stringify(value), { headers: { 'Content-Type': 'application/json' } });
const options = { expectedRevision: 12, idempotencyKey: 'synthetic-original-reconciliation-key' };
const parse = item => nativeReconciliationRequestMetadata([item], agreement);
async function clientFor(value) {
 const calls = []; const client = new WholepactClient({ token: 'synthetic', fetch: async (url, options) => { calls.push({ url, options }); return json(calls.length === 1 ? session : value); } });
 await client.connect(); return { client, calls };
}

test('both inert request kinds send exact identifiers with revision, idempotency and CSRF, never authority', async () => {
 for (const kind of ['provider_observation', 'independent_record_resolution']) {
  const { client, calls } = await clientFor(view(kind));
  assert.deepEqual(await client.requestNativeReconciliation(agreement, input(kind), options), view(kind));
  assert.equal(calls.length, 2); assert.equal(calls[1].url, `http://127.0.0.1:4318/v1/agreements/${agreement}/native-reconciliation-requests`);
  assert.equal(calls[1].options.method, 'POST'); assert.deepEqual(JSON.parse(calls[1].options.body), input(kind));
  assert.equal(calls[1].options.headers.get('If-Match'), '"12"');
  assert.equal(calls[1].options.headers.get('Idempotency-Key'), options.idempotencyKey);
  assert.equal(calls[1].options.headers.get('X-Wholepact-CSRF'), session.csrf_token);
 }
});
test('strict tagged requests reject raw evidence, credentials, source overrides, coercion and crossed variants before fetch', async () => {
 const { client, calls } = await clientFor(view());
 for (const kind of ['provider_observation', 'independent_record_resolution']) {
  for (const field of ['candidate_id', 'operation_id', 'submission_journal_identity', 'source', 'provider', 'endpoint', 'report', 'observations', 'raw_transaction', 'private_record', 'key', 'approved', 'consent', 'resolution_commit', 'signer', 'local_node']) {
   assert.throws(() => client.requestNativeReconciliation(agreement, { ...input(kind), [field]: 'untrusted' }, options), field);
  }
 }
 for (const invalid of [null, [], {}, { ...input(), kind: ['provider_observation'] }, { ...input(), kind: 'resolve' }, { ...input(), participant_id: 'participant' }, { ...input(), record_id: 'record' }, { ...input(), dispatch_request_id: [dispatchId] }, { ...input(), dispatch_request_id: 'A'.repeat(64) }, { ...input('independent_record_resolution'), participant_id: '.' }, { ...input('independent_record_resolution'), record_id: '..' }, { ...input('independent_record_resolution'), participant_id: '' }, { ...input('independent_record_resolution'), record_id: 'x'.repeat(129) }]) assert.throws(() => client.requestNativeReconciliation(agreement, invalid, options));
 assert.throws(() => client.requestNativeReconciliation(agreement, input(), { idempotencyKey: options.idempotencyKey }));
 for (const scope of [[agreement], null, { toString: () => agreement }]) {
  assert.throws(() => client.requestNativeReconciliation(scope, input(), options)); assert.throws(() => client.nativeReconciliationRequests(scope));
  assert.throws(() => client.nativeReconciliationRequest(scope, requestId)); assert.throws(() => client.withdrawNativeReconciliationRequest(scope, requestId, options));
 }
 assert.equal(calls.length, 1);
});
test('queued, withdrawn, empty and historical outcomes never reset a started request or convert provider data to independent success', () => {
 for (const kind of ['provider_observation', 'independent_record_resolution']) for (const item of [view(kind), { ...view(kind), state: 'withdrawn' }, started(kind), historical([empty()], kind), historical([snapshot()], kind)]) assert.deepEqual(parse(item), [item]);
 assert.equal(parse(historical())[0].outcome_status, 'historical_observation_recorded');
 assert.equal(parse(historical([snapshot()], 'independent_record_resolution'))[0].outcome_status, 'attempted_outcome_unknown');
 assert.equal(parse(resolved())[0].state, 'attempt_started'); assert.equal(parse(resolved())[0].resolution_commit.observation_stale, true);
 for (const patch of [{ outcome_status: 'historical_resolution_commit_recorded' }, { state: 'completed' }, { state: 'queued', attempt_revision: null }, { resolution_commit: resolved().resolution_commit }]) assert.throws(() => parse({ ...historical(), ...patch }));
 assert.throws(() => parse({ ...historical([snapshot()], 'independent_record_resolution'), outcome_status: 'historical_observation_recorded' }));
 assert.throws(() => parse({ ...started(), observations: [empty()], outcome_status: 'historical_observation_recorded' }));
 assert.throws(() => parse({ ...resolved(), resolution_commit: { ...resolved().resolution_commit, observation_stale: false } }));
 assert.throws(() => parse({ ...resolved(), resolution_commit: { ...resolved().resolution_commit, evidence_id: 'private' } }));
});
test('strict metadata binds the original dispatch operation and journal, complete source and exact variant shape', () => {
 for (const patch of [{ schema_version: '1' }, { operation: 'execute' }, { agreement_id: 'outside' }, { request_id: [requestId] }, { dispatch_request_id: 'x' }, { operation_id: `native-dispatch-${requestId}` }, { submission_journal_identity: null }, { submission_journal_identity: '0'.repeat(64) }, { signed: { ...view().signed, signatures_complete: false } }, { checkpoint_id: 'other' }, { original_revision: '12' }, { queued_revision: 15 }, { attempt_revision: 14 }, { state: ['queued'] }, { authorization_allowed: true }, { result_status: 'settled' }, { participant_id: 'extra' }, { record_id: 'extra' }, { report: report() }, { outcome_status: 'attempted_outcome_unknown' }]) assert.throws(() => parse({ ...view(), ...patch }), JSON.stringify(patch));
 for (const patch of [{ attempt_revision: null }, { attempt_revision: 15 }, { original_revision: Number.MAX_SAFE_INTEGER, queued_revision: Number.MAX_SAFE_INTEGER + 1 }, { outcome_status: 'not_attempted' }]) assert.throws(() => parse({ ...started(), ...patch }));
 assert.throws(() => parse({ ...view('independent_record_resolution'), participant_id: null }));
 assert.throws(() => parse({ ...view('independent_record_resolution'), record_id: '..' }));
});
test('provider report parser accepts only stale bounded nonauthoritative original metadata', () => {
 for (const patch of [{ transaction_id: 'b'.repeat(64) }, { expiry_height: 1 }, { state: { status: 'confirmation_policy_met', confirmations: 10 } }, { state: { status: 'stale', approved: true } }, { observed_at_unix_seconds: '1800000000' }, { valid_until_unix_seconds: 1 }, { confidence_lost: 'true' }, { independently_consensus_verified: true }, { clears_authorization_exposure: true }, { permits_replacement: true }, { endpoint: 'https://provider' }, { source_ids: ['unknown-source'] }, { source_ids: ['synthetic-source', 'synthetic-source'] }, { source_tips: [{ source_id: 'unknown-source', tip: report().last_inclusion }] }, { last_inclusion: { height: 0, hash: 'a'.repeat(64) } }, { last_inclusion: { height: 1, hash: '0'.repeat(64) } }]) assert.throws(() => parse(historical([{ ...snapshot(), report: { ...report(), ...patch } }])));
 for (const policy of [{ ...report().policy, sources: [] }, { ...report().policy, sources: ['https://provider'] }, { ...report().policy, sources: ['a', 'a'] }, { ...report().policy, sources: Array.from({ length: 9 }, (_, i) => `source-${i}`) }, { ...report().policy, required_confirmations: 0 }, { ...report().policy, required_confirmations: '10' }, { ...report().policy, expiry_observation_depth: 101 }, { ...report().policy, approved: true }]) assert.throws(() => parse(historical([{ ...snapshot(), report: { ...report(), policy } }])));
 assert.throws(() => parse(historical([{ ...empty(), report: report() }])));
 assert.throws(() => parse(historical([{ ...snapshot(), raw_provider_report: 'extra' }])));
 assert.doesNotThrow(() => parse(historical([{ ...snapshot(), report: { ...report(), last_inclusion: { height: 4294967296, hash: 'A'.repeat(64) } } }])));
});
test('snapshot sequence preserves append-only submission and report lineage without hiding reorganization', () => {
 const next = { ...snapshot(), report: { ...report(), observed_at_unix_seconds: report().observed_at_unix_seconds + 1, confidence_lost: true, reorganization_observed: true, last_inclusion: { height: 3499998, hash: 'b'.repeat(64) } } };
 assert.doesNotThrow(() => parse(historical([empty(), snapshot(), next])));
 for (const after of [empty(), snapshot(), { ...snapshot(), report: null }, { ...snapshot(), report: { ...report(), observed_at_unix_seconds: report().observed_at_unix_seconds - 1 } }, { ...snapshot(), report: { ...report(), last_inclusion: null } }, { ...snapshot(), report: { ...report(), policy: { ...report().policy, required_confirmations: 11 } } }]) assert.throws(() => parse(historical([snapshot(), after])));
 assert.throws(() => parse(historical([{ ...snapshot(), submission: { ...snapshot().submission, submission_journal_identity: 'c'.repeat(64) } }])));
 const changed = { ...next, submission: { ...next.submission, descriptor: { ...next.submission.descriptor, obligation_id: 'changed-obligation-001' } } };
 assert.throws(() => parse(historical([snapshot(), changed])));
});
test('distinct later requests preserve every started identity while queued collisions and changed originals fail closed', () => {
 const later = { ...view(), request_id: '1'.repeat(64), original_revision: 15, queued_revision: 16 };
 assert.doesNotThrow(() => nativeReconciliationRequestMetadata([started(), later], agreement));
 assert.doesNotThrow(() => nativeReconciliationRequestMetadata([{ ...view(), state: 'withdrawn' }, later], agreement));
 assert.throws(() => nativeReconciliationRequestMetadata([view(), later], agreement));
 assert.throws(() => nativeReconciliationRequestMetadata([started(), { ...later, transaction_digest: '2'.repeat(64) }], agreement));
 const independentLater = { ...view('independent_record_resolution'), request_id: '2'.repeat(64), original_revision: 15, queued_revision: 16 };
 assert.doesNotThrow(() => nativeReconciliationRequestMetadata([resolved(), independentLater], agreement));
 assert.doesNotThrow(() => nativeReconciliationRequestMetadata([view(), independentLater], agreement));
 assert.throws(() => nativeReconciliationRequestMetadata([view('independent_record_resolution'), independentLater], agreement));
 assert.throws(() => nativeReconciliationRequestMetadata([resolved(), { ...independentLater, participant_id: 'different-participant' }], agreement));
 for (const invalid of [null, {}, [view(), view()], Array.from({ length: 17 }, () => view())]) assert.throws(() => nativeReconciliationRequestMetadata(invalid, agreement));
 const observations = Array.from({ length: 16 }, (_, index) => ({ ...snapshot(), report: { ...report(), observed_at_unix_seconds: 1800000000 + index } }));
 assert.doesNotThrow(() => parse(historical(observations))); assert.throws(() => parse(historical([...observations, observations[0]])));
});
test('malformed or changed mutation acknowledgement remains uncertain, and caller mutation cannot change original binding', async () => {
 for (const patch of [{ dispatch_request_id: '0'.repeat(64) }, { agreement_id: 'outside' }, { original_revision: 15, queued_revision: 16 }, { authorization_allowed: true }, { state: 'completed' }, { kind: 'independent_record_resolution', participant_id: 'p', record_id: 'r' }]) {
  const { client, calls } = await clientFor({ ...view(), ...patch });
  await assert.rejects(client.requestNativeReconciliation(agreement, input(), options), error => error instanceof WholepactError && error.code === 'EXTERNAL_OUTCOME_UNCERTAIN' && error.details.dispatch_request_id === dispatchId && error.details.idempotency_key === options.idempotencyKey);
  assert.equal(calls.length, 2);
 }
 const wrong = await clientFor({ ...view('independent_record_resolution'), record_id: 'different-record' });
 await assert.rejects(wrong.client.requestNativeReconciliation(agreement, input('independent_record_resolution'), options), error => error.code === 'EXTERNAL_OUTCOME_UNCERTAIN');
 const { client } = await clientFor(view('independent_record_resolution')); const body = input('independent_record_resolution'); const command = { ...options };
 const pending = client.requestNativeReconciliation(agreement, body, command); body.record_id = 'changed'; body.dispatch_request_id = '0'.repeat(64); command.expectedRevision = 99;
 assert.deepEqual(await pending, view('independent_record_resolution'));
});
test('list, exact read and queued-only withdrawal use inert routes and validate exact acknowledgement', async () => {
 const list = await clientFor([historical(), { ...resolved(), request_id: '1'.repeat(64) }]);
 assert.equal((await list.client.nativeReconciliationRequests(agreement)).length, 2); assert.equal(list.calls[1].options.method, 'GET');
 const one = await clientFor(historical()); assert.deepEqual(await one.client.nativeReconciliationRequest(agreement, requestId), historical());
 assert.equal(one.calls[1].url.endsWith(`/${requestId}`), true);
 await assert.rejects(one.client.nativeReconciliationRequest(agreement, '0'.repeat(64)), error => error.code === 'INVALID_RESPONSE');
 const withdrawn = await clientFor({ ...view(), state: 'withdrawn' });
 await withdrawn.client.withdrawNativeReconciliationRequest(agreement, requestId, { ...options, expectedRevision: 13 });
 assert.equal(withdrawn.calls[1].url.endsWith(`/${requestId}/withdraw`), true); assert.deepEqual(JSON.parse(withdrawn.calls[1].options.body), {});
 for (const invalid of [view(), started(), historical(), resolved(), { ...view(), state: 'withdrawn', request_id: '0'.repeat(64) }]) {
  const fixture = await clientFor(invalid); await assert.rejects(fixture.client.withdrawNativeReconciliationRequest(agreement, requestId, options), error => error.code === 'EXTERNAL_OUTCOME_UNCERTAIN'); assert.equal(fixture.calls.length, 2);
 }
 for (const invalid of [null, [view(), view()], [{ ...view(), retry_allowed: true }]]) {
  const fixture = await clientFor(invalid); await assert.rejects(fixture.client.nativeReconciliationRequests(agreement), error => error.code === 'INVALID_RESPONSE');
 }
 assert.throws(() => one.client.nativeReconciliationRequest(agreement, 'not-exact')); assert.throws(() => one.client.withdrawNativeReconciliationRequest(agreement, 'not-exact', options));
});
test('lost or invalid mutation responses do not repeat observation, resolution or request creation', async () => {
 for (const kind of ['provider_observation', 'independent_record_resolution']) for (const response of [() => { throw new TypeError('synthetic lost acknowledgement'); }, () => new Response('{', { headers: { 'Content-Type': 'application/json' } })]) {
  let calls = 0; const client = new WholepactClient({ token: 'synthetic', fetch: async () => ++calls === 1 ? json(session) : response() });
  await client.connect(); await assert.rejects(client.requestNativeReconciliation(agreement, input(kind), options), error => error.code === 'EXTERNAL_OUTCOME_UNCERTAIN'); assert.equal(calls, 2);
 }
});
