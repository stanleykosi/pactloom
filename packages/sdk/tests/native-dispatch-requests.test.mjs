import { test } from 'node:test';
import assert from 'node:assert/strict';
import { WholepactClient, WholepactError, nativeDispatchRequestMetadata } from '../dist/index.js';
import { agreement, transactionId, requestId, journalId, view, started, empty, snapshot, attempt, historical } from './native-dispatch-fixtures.mjs';
const session = { session_token: 'synthetic-session', csrf_token: 'synthetic-csrf' };
const json = value => new Response(JSON.stringify(value), { headers: { 'Content-Type': 'application/json' } });
const options = { expectedRevision: 10, idempotencyKey: 'synthetic-original-dispatch-key' };
const input = { transaction_request_id: transactionId };
const parse = item => nativeDispatchRequestMetadata([item], agreement);
async function clientFor(value) {
 const calls = []; const client = new WholepactClient({ token: 'synthetic', fetch: async (url, options) => { calls.push({ url, options }); return json(calls.length === 1 ? session : value); } });
 await client.connect(); return { client, calls };
}

test('inert dispatch request sends only the original transaction request ID and exact command headers', async () => {
 const { client, calls } = await clientFor(view());
 assert.deepEqual(await client.requestNativeDispatch(agreement, input, options), view());
 assert.equal(calls.length, 2);
 assert.equal(calls[1].url, `http://127.0.0.1:4318/v1/agreements/${agreement}/native-dispatch-requests`);
 assert.equal(calls[1].options.method, 'POST');
 assert.deepEqual(JSON.parse(calls[1].options.body), input);
 assert.equal(calls[1].options.headers.get('If-Match'), '"10"');
 assert.equal(calls[1].options.headers.get('Idempotency-Key'), options.idempotencyKey);
 assert.equal(calls[1].options.headers.get('X-Wholepact-CSRF'), session.csrf_token);
});
test('caller cannot supply provider, key, bytes, operation, approval or source overrides', async () => {
 const { client, calls } = await clientFor(view());
 for (const field of ['candidate_id', 'job_id', 'intake_request_id', 'signature_retention_key', 'signed', 'checkpoint_id', 'transaction_digest', 'txid', 'operation_id', 'provider', 'backend', 'transaction_bytes', 'key', 'approved', 'approval', 'submission_journal_identity', 'observations']) {
  assert.throws(() => client.requestNativeDispatch(agreement, { ...input, [field]: 'untrusted' }, options), field);
 }
 for (const invalid of [{ transaction_request_id: ['a'.repeat(64)] }, { transaction_request_id: 'a'.repeat(63) }, { transaction_request_id: 'A'.repeat(64) }, {}, [], null, 'source']) {
  assert.throws(() => client.requestNativeDispatch(agreement, invalid, options));
 }
 assert.throws(() => client.requestNativeDispatch(agreement, input, { idempotencyKey: options.idempotencyKey }));
 for (const scope of [[agreement], null, { toString: () => agreement }]) {
  assert.throws(() => client.requestNativeDispatch(scope, input, options));
  assert.throws(() => client.nativeDispatchRequests(scope));
  assert.throws(() => client.nativeDispatchRequest(scope, requestId));
  assert.throws(() => client.withdrawNativeDispatchRequest(scope, requestId, options));
 }
 assert.equal(calls.length, 1);
});
test('queued, withdrawn, started, empty and populated snapshots preserve historical meaning', () => {
 for (const item of [view(), { ...view(), state: 'withdrawn' }, started(), { ...started(), observations: [empty()] }, historical(), historical([empty(), snapshot()])]) assert.deepEqual(parse(item), [item]);
 assert.equal(parse({ ...started(), observations: [empty()] })[0].outcome_status, 'attempted_outcome_unknown');
 assert.throws(() => parse({ ...started(), observations: [empty()], outcome_status: 'historical_result_recorded' }));
 assert.throws(() => parse({ ...historical(), outcome_status: 'attempted_outcome_unknown' }));
});
test('strict metadata rejects coercion, extra authority and malformed source or revision identities', () => {
 for (const patch of [
  { schema_version: '1' }, { operation: 'execute' }, { agreement_id: 'other' }, { request_id: ['b'.repeat(64)] },
  { state: ['queued'] }, { state: 'completed' }, { authorization_allowed: true }, { result_status: 'settled' }, { approved: true },
  { kind: 'dispatch' }, { signed: { ...view().signed, signatures_complete: false } }, { signed: { ...view().signed, approved: true } },
  { signed: { ...view().signed, result_id: 'arbitrary' } }, { signature_retention_key: 'caller-key' }, { checkpoint_id: 'arbitrary' },
  { operation_id: 'caller-operation' }, { job_id: 'arbitrary' }, { manifest_digest: 'short' }, { transaction_digest: 'short' }, { txid: 'short' },
  { original_revision: 0, queued_revision: 1 }, { original_revision: '10' }, { queued_revision: 12 }, { queued_revision: Number.MAX_SAFE_INTEGER + 1 },
  { attempt_revision: 12 }, { outcome_status: 'attempted_outcome_unknown' }, { submission_journal_identity: journalId }, { observations: [empty()] },
 ]) assert.throws(() => parse({ ...view(), ...patch }), JSON.stringify(patch));
 for (const patch of [{ submission_journal_identity: null }, { submission_journal_identity: '' }, { submission_journal_identity: '0'.repeat(64) }, { submission_journal_identity: 'F'.repeat(64) }, { attempt_revision: 13 }, { attempt_revision: '12' }, { outcome_status: 'not_attempted' }]) assert.throws(() => parse({ ...started(), ...patch }));
});
test('descriptor, intent, journal and attempt shape bind only to the immutable original transaction', () => {
 for (const patch of [{ submission_journal_identity: '1'.repeat(64) }, { broadcast: true }, { intent: null }, { descriptor: null }, { attempts: [attempt(), attempt()] }]) assert.throws(() => parse(historical([{ ...snapshot(), ...patch }])));
 for (const [field, value] of [['operation_id', 'caller-operation'], ['obligation_id', 'short'], ['proposal_id', 'other-candidate-001'], ['transaction_id', 'b'.repeat(64)], ['bytes_sha256', '1'.repeat(64)], ['network', 'mainnet'], ['expiry_height', 0], ['expiry_height', '3500000'], ['expiry_height', 4294967296], ['consensus_branch_id', 0], ['approved', true]]) {
  assert.throws(() => parse(historical([{ ...snapshot(), descriptor: { ...snapshot().descriptor, [field]: value } }])), field);
 }
 for (const patch of [{ operation_id: 'caller-operation' }, { bytes_sha256: '1'.repeat(64) }, { historical_provider_state: 'confirmed' }, { historical_provider_state: ['submission_unknown'] }, { settlement_verified: true }]) assert.throws(() => parse(historical([{ ...snapshot(), intent: { ...snapshot().intent, ...patch } }])));
 for (const patch of [{ number: 0 }, { number: '1' }, { source_id: 'https://provider' }, { source_id: '' }, { started_at_unix_seconds: -1 }, { started_at_unix_seconds: Number.MAX_SAFE_INTEGER + 1 }, { authorization_allowed: true }]) assert.throws(() => parse(historical([{ ...snapshot(), attempts: [{ ...attempt(), ...patch }] }])));
 assert.throws(() => parse({ ...started(), observations: [{ ...empty(), attempts: [attempt()] }] }));
});
test('all typed historical outcomes remain evidence only and integer error codes never coerce', () => {
 const outcomes = [
  { kind: 'unknown' }, { kind: 'acknowledged' }, { kind: 'blocked_before_dispatch' }, { kind: 'rejected', code: -26 },
  ...['timeout', 'interrupted', 'transport_unavailable', 'resource_limit', 'malformed_evidence', 'unsupported_capability', 'other'].map(code => ({ kind: 'indeterminate', reason: { code } })),
  { kind: 'indeterminate', reason: { code: 'backend', grpc_code: 14 } },
 ];
 for (const outcome of outcomes) assert.equal(parse(historical([{ ...snapshot(), attempts: [attempt(1, outcome)] }]))[0].authorization_allowed, false);
 for (const outcome of [{ kind: ['unknown'] }, { kind: 'confirmed' }, { kind: 'acknowledged', paid: true }, { kind: 'rejected', code: 0 }, { kind: 'rejected', code: '1' }, { kind: 'rejected', code: 2147483648 }, { kind: 'indeterminate', reason: { code: 'backend', grpc_code: '14' } }, { kind: 'indeterminate', reason: { code: 'timeout', retry_allowed: true } }, { kind: 'indeterminate', reason: { code: 'unknown' } }]) assert.throws(() => parse(historical([{ ...snapshot(), attempts: [attempt(1, outcome)] }])));
});
test('snapshot progression is append-only and terminal outcomes, identities and timestamps cannot change', () => {
 const unknown = { ...snapshot(), attempts: [attempt()] };
 const acknowledged = { ...snapshot(), intent: { ...snapshot().intent, historical_provider_state: 'backend_acknowledged' }, attempts: [attempt(1, { kind: 'acknowledged' })] };
 const laterUnknown = { ...acknowledged, attempts: [...acknowledged.attempts, attempt(2)] };
 const laterIndeterminate = { ...laterUnknown, attempts: [acknowledged.attempts[0], attempt(2, { kind: 'indeterminate', reason: { code: 'timeout' } })] };
 const checked = parse(historical([empty(), unknown, acknowledged, laterUnknown, laterIndeterminate]))[0];
 assert.equal(checked.observations.at(-1).intent.historical_provider_state, 'backend_acknowledged');
 assert.equal(checked.observations.at(-1).attempts.at(-1).outcome.kind, 'indeterminate');
 for (const next of [
  empty(), unknown, { ...acknowledged, attempts: [] }, { ...acknowledged, intent: { ...acknowledged.intent, historical_provider_state: 'backend_rejected' } },
  { ...acknowledged, descriptor: { ...acknowledged.descriptor, obligation_id: 'different-obligation-001' } },
  ...[{ source_id: 'different-provider' }, { started_at_unix_seconds: attempt().started_at_unix_seconds + 1 }, { outcome: { kind: 'rejected', code: -1 } }].map(patch => ({ ...acknowledged, attempts: [{ ...acknowledged.attempts[0], ...patch }] })),
 ]) assert.throws(() => parse(historical([acknowledged, next])));
 assert.throws(() => parse(historical([unknown, unknown])));
 assert.throws(() => parse(historical([unknown, acknowledged, unknown])));
 assert.throws(() => parse(historical([{ ...snapshot(), attempts: [attempt(), { ...attempt(2), started_at_unix_seconds: attempt().started_at_unix_seconds - 1 }] }])));
 const rejected = { ...unknown, intent: { ...unknown.intent, historical_provider_state: 'backend_rejected' }, attempts: [attempt(1, { kind: 'rejected', code: -26 })] };
 assert.doesNotThrow(() => parse(historical([unknown, rejected, { ...rejected, intent: { ...rejected.intent, historical_provider_state: 'backend_acknowledged' }, attempts: [...rejected.attempts, attempt(2, { kind: 'acknowledged' })] }])));
});
test('bounded inventories, snapshots and attempts reject oversized or duplicate retained history', () => {
 for (const invalid of [null, {}, [view(), view()], Array.from({ length: 17 }, () => view())]) assert.throws(() => nativeDispatchRequestMetadata(invalid, agreement));
 assert.throws(() => parse(historical(Array.from({ length: 17 }, () => snapshot()))));
 assert.throws(() => parse(historical([{ ...snapshot(), attempts: Array.from({ length: 129 }, (_, i) => attempt(i + 1)) }])));
 assert.doesNotThrow(() => parse(historical([{ ...snapshot(), attempts: Array.from({ length: 128 }, (_, i) => attempt(i + 1)) }])));
 const observations = Array.from({ length: 16 }, (_, i) => ({ ...snapshot(), attempts: Array.from({ length: i }, (_, j) => attempt(j + 1)) }));
 assert.doesNotThrow(() => parse(historical(observations)));
});
test('safe withdrawn history permits one new queued identity without permitting a changed original source', () => {
 const withdrawn = { ...view(), state: 'withdrawn' };
 const replacement = { ...view(), request_id: '1'.repeat(64), operation_id: 'native-dispatch-' + '1'.repeat(64), original_revision: 12, queued_revision: 13 };
 assert.doesNotThrow(() => nativeDispatchRequestMetadata([withdrawn, replacement], agreement));
 assert.throws(() => nativeDispatchRequestMetadata([view(), replacement], agreement));
 assert.throws(() => nativeDispatchRequestMetadata([withdrawn, { ...replacement, manifest_digest: '2'.repeat(64) }], agreement));
 assert.throws(() => nativeDispatchRequestMetadata([withdrawn, { ...replacement, signed: { ...replacement.signed, result_id: 'signed-' + '2'.repeat(64) } }], agreement));
});
test('malformed mutation acknowledgement preserves original identity as an uncertain outcome', async () => {
 for (const patch of [{ transaction_request_id: '0'.repeat(64) }, { original_revision: 13, queued_revision: 14 }, { agreement_id: 'other' }, { operation_id: 'other-operation' }, { authorization_allowed: true }, { observations: [empty()] }, { state: 'completed' }]) {
  const { client, calls } = await clientFor({ ...view(), ...patch });
  await assert.rejects(client.requestNativeDispatch(agreement, input, options), error => error instanceof WholepactError && error.code === 'EXTERNAL_OUTCOME_UNCERTAIN' && error.details.transaction_request_id === transactionId && error.details.idempotency_key === options.idempotencyKey);
  assert.equal(calls.length, 2);
 }
});
test('caller mutation after enqueue cannot change the original response binding', async () => {
 const { client } = await clientFor(view()); const body = { ...input }; const command = { ...options };
 const pending = client.requestNativeDispatch(agreement, body, command);
 body.transaction_request_id = '0'.repeat(64); command.expectedRevision = 99;
 assert.deepEqual(await pending, view());
});
test('list and exact read validate retained metadata and never call execution or status-refresh routes', async () => {
 const { client, calls } = await clientFor([historical()]);
 assert.deepEqual(await client.nativeDispatchRequests(agreement), [historical()]);
 assert.equal(calls[1].options.method, 'GET');
 const one = await clientFor(historical());
 assert.deepEqual(await one.client.nativeDispatchRequest(agreement, requestId), historical());
 assert.equal(one.calls[1].url.endsWith(`/native-dispatch-requests/${requestId}`), true);
 await assert.rejects(one.client.nativeDispatchRequest(agreement, '0'.repeat(64)), error => error.code === 'INVALID_RESPONSE');
 for (const invalid of [null, [view(), view()], [{ ...view(), retry_allowed: true }]]) {
  const fixture = await clientFor(invalid); await assert.rejects(fixture.client.nativeDispatchRequests(agreement), error => error.code === 'INVALID_RESPONSE');
 }
 assert.throws(() => one.client.nativeDispatchRequest(agreement, 'not-an-exact-request'));
 assert.throws(() => one.client.withdrawNativeDispatchRequest(agreement, 'not-an-exact-request', options));
});
test('only confirmed queued withdrawal is acknowledged, without forgetting attempted history', async () => {
 const { client, calls } = await clientFor({ ...view(), state: 'withdrawn' });
 await client.withdrawNativeDispatchRequest(agreement, requestId, { ...options, expectedRevision: 11 });
 assert.equal(calls[1].url.endsWith(`/${requestId}/withdraw`), true); assert.deepEqual(JSON.parse(calls[1].options.body), {});
 for (const invalid of [view(), started(), historical(), { ...view(), state: 'withdrawn', request_id: '0'.repeat(64), operation_id: 'native-dispatch-' + '0'.repeat(64) }]) {
  const fixture = await clientFor(invalid);
  await assert.rejects(fixture.client.withdrawNativeDispatchRequest(agreement, requestId, options), error => error.code === 'EXTERNAL_OUTCOME_UNCERTAIN');
  assert.equal(fixture.calls.length, 2);
 }
});
test('lost or invalid mutation acknowledgements remain uncertain without automatic retries', async () => {
 for (const response of [() => { throw new TypeError('synthetic lost response'); }, () => new Response('{', { headers: { 'Content-Type': 'application/json' } })]) {
  let calls = 0; const client = new WholepactClient({ token: 'synthetic', fetch: async () => ++calls === 1 ? json(session) : response() });
  await client.connect(); await assert.rejects(client.requestNativeDispatch(agreement, input, options), error => error.code === 'EXTERNAL_OUTCOME_UNCERTAIN'); assert.equal(calls, 2);
 }
});
