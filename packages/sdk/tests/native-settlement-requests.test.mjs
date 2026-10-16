import { test } from 'node:test';
import assert from 'node:assert/strict';
import { WholepactClient, WholepactError, nativeSettlementRequestMetadata } from '../dist/index.js';
const intake = 'a'.repeat(64);
const view = () => ({
 schema_version: 1, operation: 'settlement_handoff', request_id: 'b'.repeat(64), agreement_id: 'agreement', candidate_id: 'candidate', manifest_digest: 'c'.repeat(64),
 original_revision: 7, queued_revision: 8, attempt_revision: null, state: 'queued', authorization_allowed: false, result_status: 'historical_metadata_only',
 kind: 'signature_reconcile', intake_request_id: intake, job_id: 'proof-' + 'd'.repeat(64), signature_retention_key: `native-artifact-handoff-${intake}`,
 proved_artifact_digest: 'e'.repeat(64), receipt_storage_key: 'f'.repeat(64), receipt_digest: '1'.repeat(64), scope_digest: '2'.repeat(64), coordination_request_digest: '3'.repeat(64),
 observation: null, outcome_status: 'not_attempted',
});
const evidence = () => ({ result_id: 'signed-' + '4'.repeat(64), request_digest: '5'.repeat(64), signed_candidate_digest: '6'.repeat(64), signatures_complete: true });
const started = () => ({ ...view(), state: 'attempt_started', attempt_revision: 9, outcome_status: 'attempted_outcome_unknown' });
const signed = () => ({ ...started(), outcome_status: 'historical_result_recorded', observation: { type: 'signed', evidence: evidence() } });
const transaction = () => ({ ...started(), kind: 'transaction_checkpoint', outcome_status: 'historical_result_recorded', observation: { type: 'transaction', signed: evidence(), checkpoint_id: 'transaction-' + '7'.repeat(64), transaction_digest: '8'.repeat(64), txid: '9'.repeat(64) } });
const session = { session_token: 'synthetic-session', csrf_token: 'synthetic-csrf' };
const json = value => new Response(JSON.stringify(value), { headers: { 'Content-Type': 'application/json' } });
const options = { expectedRevision: 7, idempotencyKey: 'synthetic-original-settlement-key' };
const input = { intake_request_id: intake, kind: 'signature_reconcile' };
async function clientFor(value) {
 const calls = []; const client = new WholepactClient({ token: 'synthetic', fetch: async (url, options) => { calls.push({ url, options }); return json(calls.length === 1 ? session : value); } });
 await client.connect(); return { client, calls };
}

test('metadata-only settlement request sends the original intake ID and kind with exact command headers', async () => {
 const { client, calls } = await clientFor(view());
 await client.requestNativeSettlement('agreement', input, options);
 assert.equal(calls.length, 2);
 assert.equal(calls[1].url, 'http://127.0.0.1:4318/v1/agreements/agreement/native-settlement-requests');
 assert.deepEqual(JSON.parse(calls[1].options.body), input);
 assert.equal(calls[1].options.headers.get('If-Match'), '"7"');
 assert.equal(calls[1].options.headers.get('Idempotency-Key'), options.idempotencyKey);
 assert.equal(calls[1].options.headers.get('X-Wholepact-CSRF'), session.csrf_token);
});
test('caller-supplied result identity and unsupported kinds are rejected before transmission', async () => {
 const { client, calls } = await clientFor(view());
 for (const field of ['candidate_id', 'job_id', 'result_id', 'signature_retention_key', 'request_digest', 'signed_candidate_digest', 'checkpoint_id', 'transaction_digest', 'txid', 'approved', 'observation']) {
  assert.throws(() => client.requestNativeSettlement('agreement', { ...input, [field]: 'untrusted' }, options));
 }
 for (const invalid of [{ ...input, kind: 'transaction_dispatch' }, { ...input, intake_request_id: 'not-an-original-id' }, { kind: input.kind }, null]) assert.throws(() => client.requestNativeSettlement('agreement', invalid, options));
 assert.throws(() => client.requestNativeSettlement('agreement', input, { idempotencyKey: options.idempotencyKey }));
 assert.equal(calls.length, 1);
});
test('queued, withdrawn, unknown and exact historical results retain their distinct meanings', () => {
 for (const item of [view(), { ...view(), state: 'withdrawn' }, started(), signed(), transaction(), { ...signed(), observation: { type: 'signed', evidence: { ...evidence(), signatures_complete: false } } }]) {
  assert.deepEqual(nativeSettlementRequestMetadata([item], 'agreement'), [item]);
 }
 assert.equal(nativeSettlementRequestMetadata([started()], 'agreement')[0].observation, null);
});
test('malformed response never acknowledges a mutation and preserves original request identity', async () => {
 const patches = [
  { kind: 'transaction_checkpoint' }, { kind: ['signature_reconcile'] }, { state: ['queued'] }, { intake_request_id: '0'.repeat(64), signature_retention_key: 'native-artifact-handoff-' + '0'.repeat(64) },
  { original_revision: 10, queued_revision: 11 }, { agreement_id: 'other' }, { operation: 'execute' }, { authorization_allowed: true },
  { result_status: 'completed' }, { outcome_status: 'historical_result_recorded' }, { state: 'completed' }, { signature_retention_key: 'native-artifact-handoff-' + '0'.repeat(64) },
  { observation: { type: 'signed', evidence: evidence() } }, { approved: true }, { proved_artifact_digest: 'short' },
 ];
 for (const patch of patches) {
  const { client, calls } = await clientFor({ ...view(), ...patch });
  await assert.rejects(client.requestNativeSettlement('agreement', input, options), error => error instanceof WholepactError && error.code === 'EXTERNAL_OUTCOME_UNCERTAIN' && error.details.idempotency_key === options.idempotencyKey && error.details.intake_request_id === intake);
  assert.equal(calls.length, 2);
 }
});
test('observations reject cross-kind results, incomplete extraction and financial authority claims', () => {
 const invalid = [
  { ...signed(), kind: 'transaction_checkpoint' }, { ...transaction(), kind: 'signature_reconcile' },
  { ...transaction(), observation: { ...transaction().observation, signed: { ...evidence(), signatures_complete: false } } },
  { ...signed(), observation: { type: 'signed', evidence: { ...evidence(), authorization_allowed: true } } },
  { ...transaction(), observation: { ...transaction().observation, broadcast: true } },
  { ...signed(), observation: { type: 'signed', evidence: { ...evidence(), result_id: 'arbitrary' } } },
  { ...transaction(), observation: { ...transaction().observation, checkpoint_id: 'arbitrary' } },
  { ...transaction(), observation: { ...transaction().observation, txid: 'malformed' } },
  { ...started(), outcome_status: 'not_attempted' }, { ...signed(), outcome_status: 'attempted_outcome_unknown' },
  { ...view(), queued_revision: 9 }, { ...started(), attempt_revision: 10 }, { ...view(), original_revision: Number.MAX_SAFE_INTEGER, queued_revision: Number.MAX_SAFE_INTEGER + 1 },
 ];
 for (const item of invalid) assert.throws(() => nativeSettlementRequestMetadata([item], 'agreement'));
});
test('list and exact read validate cardinality, identity and historical metadata without invoking work', async () => {
 for (const invalid of [null, {}, [view(), view()], Array.from({ length: 17 }, () => view()), [{ ...view(), settlement_verified: true }], [{ ...view(), kind: ['signature_reconcile'] }], [{ ...view(), state: ['queued'] }]]) {
  const { client, calls } = await clientFor(invalid);
  await assert.rejects(client.nativeSettlementRequests('agreement'), error => error.code === 'INVALID_RESPONSE'); assert.equal(calls.length, 2);
 }
 const { client, calls } = await clientFor(transaction());
 assert.deepEqual(await client.nativeSettlementRequest('agreement', view().request_id), transaction());
 assert.equal(calls[1].options.method, 'GET');
 await assert.rejects(client.nativeSettlementRequest('agreement', '0'.repeat(64)), error => error.code === 'INVALID_RESPONSE');
 assert.equal(calls.length, 3);
});
test('only a confirmed never-started withdrawal is acknowledged', async () => {
 const { client, calls } = await clientFor({ ...view(), state: 'withdrawn' });
 await client.withdrawNativeSettlementRequest('agreement', view().request_id, { ...options, expectedRevision: 8 });
 assert.equal(calls[1].url.endsWith(`/${view().request_id}/withdraw`), true);
 assert.deepEqual(JSON.parse(calls[1].options.body), {});
 for (const invalid of [started(), signed(), transaction(), { ...view(), state: 'withdrawn', request_id: '0'.repeat(64) }]) {
  const { client, calls } = await clientFor(invalid);
  await assert.rejects(client.withdrawNativeSettlementRequest('agreement', view().request_id, options), error => error.code === 'EXTERNAL_OUTCOME_UNCERTAIN');
  assert.equal(calls.length, 2);
 }
});
test('lost mutation acknowledgment is uncertain and never retried automatically', async () => {
 let calls = 0;
 const client = new WholepactClient({ token: 'synthetic', fetch: async () => { if (++calls === 1) return json(session); throw new TypeError('synthetic lost response'); } });
 await client.connect();
 await assert.rejects(client.requestNativeSettlement('agreement', input, options), error => error.code === 'EXTERNAL_OUTCOME_UNCERTAIN');
 assert.equal(calls, 2);
});
