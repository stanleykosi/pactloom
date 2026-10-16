import { test } from 'node:test';
import assert from 'node:assert/strict';
import { nativeSettlementRequestMetadata, originalSettlementIntake, canRequestNativeSettlement, hasOriginalSignedObservation } from '../../src/native-settlement-request-model.ts';
const intakeId = 'a'.repeat(64);
const intake = () => ({ schema_version: 1, operation: 'artifact_handoff', kind: 'signature_intake', request_id: intakeId, agreement_id: 'agreement', candidate_id: 'candidate', manifest_digest: 'c'.repeat(64), original_revision: 4, queued_revision: 5, attempt_revision: 6, state: 'attempt_started', authorization_allowed: false, result_status: 'unknown_not_financial_evidence', job_id: 'proof-' + 'd'.repeat(64), proved_artifact_digest: 'e'.repeat(64), receipt_storage_key: 'f'.repeat(64), receipt_digest: '1'.repeat(64), scope_digest: '2'.repeat(64), coordination_request_digest: '3'.repeat(64), handoff_status: 'attempted_outcome_unknown' });
const item = () => ({ schema_version: 1, operation: 'settlement_handoff', kind: 'signature_reconcile', request_id: 'b'.repeat(64), agreement_id: 'agreement', candidate_id: 'candidate', manifest_digest: 'c'.repeat(64), original_revision: 7, queued_revision: 8, attempt_revision: null, state: 'queued', authorization_allowed: false, result_status: 'historical_metadata_only', intake_request_id: intakeId, signature_retention_key: `native-artifact-handoff-${intakeId}`, job_id: 'proof-' + 'd'.repeat(64), proved_artifact_digest: 'e'.repeat(64), receipt_storage_key: 'f'.repeat(64), receipt_digest: '1'.repeat(64), scope_digest: '2'.repeat(64), coordination_request_digest: '3'.repeat(64), outcome_status: 'not_attempted', observation: null });
const signed = () => ({ ...item(), state: 'attempt_started', attempt_revision: 9, outcome_status: 'historical_result_recorded', observation: { type: 'signed', evidence: { result_id: 'signed-' + '4'.repeat(64), request_digest: '5'.repeat(64), signed_candidate_digest: '6'.repeat(64), signatures_complete: true } } });
const can = (requests, intakes = [intake()], kind = 'signature_reconcile', allowed = true, busy = false, uncertain = false) => canRequestNativeSettlement(requests, intakes, intakeId, kind, allowed, busy, uncertain);

test('only the original started signature intake supplies source identity', () => {
 assert.equal(originalSettlementIntake([intake()], intakeId)?.request_id, intakeId);
 assert.equal(can([]), true);
 for (const source of [{ ...intake(), kind: 'signer_review' }, { ...intake(), state: 'queued', attempt_revision: null }, { ...intake(), state: 'withdrawn', attempt_revision: null }, { ...intake(), request_id: '0'.repeat(64) }]) {
  assert.equal(originalSettlementIntake([source], intakeId), undefined);
  assert.equal(can([], [source]), false);
 }
 assert.equal(can([], null), false); assert.equal(can([], []), false); assert.equal(can(null), false);
});
test('transaction checkpoint request requires exact complete historical signed observation', () => {
 assert.equal(can([], [intake()], 'transaction_checkpoint'), false);
 assert.equal(can([item()], [intake()], 'transaction_checkpoint'), false);
 assert.equal(can([{ ...item(), state: 'attempt_started', attempt_revision: 9, outcome_status: 'attempted_outcome_unknown' }], [intake()], 'transaction_checkpoint'), false);
 assert.equal(can([signed()], [intake()], 'transaction_checkpoint'), true);
 assert.equal(can([{ ...signed(), observation: { type: 'signed', evidence: { ...signed().observation.evidence, signatures_complete: false } } }], [intake()], 'transaction_checkpoint'), false);
 for (const field of ['intake_request_id', 'agreement_id', 'candidate_id', 'job_id', 'manifest_digest', 'proved_artifact_digest', 'signature_retention_key', 'receipt_storage_key', 'receipt_digest', 'scope_digest', 'coordination_request_digest']) {
  assert.equal(hasOriginalSignedObservation([{ ...signed(), [field]: 'different-original' }], intake()), false, field);
 }
 for (const field of ['result_id', 'request_digest', 'signed_candidate_digest']) {
  const changed = { ...signed(), request_id: '0'.repeat(64), observation: { type: 'signed', evidence: { ...signed().observation.evidence, [field]: 'conflicting-original' } } };
  assert.equal(hasOriginalSignedObservation([signed(), changed], intake()), false, field);
 }
});
test('unknown durable effects block same-kind replacement while separate purposes stay explicit', () => {
 const unknown = { ...item(), state: 'attempt_started', attempt_revision: 9, outcome_status: 'attempted_outcome_unknown' };
 for (const current of [item(), unknown, signed()]) assert.equal(can([current]), false);
 assert.equal(can([{ ...item(), state: 'withdrawn' }]), true);
 assert.equal(can([signed()], [intake()], 'transaction_checkpoint'), true);
 assert.equal(can([signed(), { ...item(), request_id: '0'.repeat(64), kind: 'transaction_checkpoint' }], [intake()], 'transaction_checkpoint'), false);
});
test('missing grants, stale inventory, pending work and uncertainty keep both request kinds disabled', () => {
 for (const kind of ['signature_reconcile', 'transaction_checkpoint']) {
  const requests = kind === 'signature_reconcile' ? [] : [signed()];
  assert.equal(can(requests, [intake()], kind, false), false);
  assert.equal(can(requests, [intake()], kind, true, true), false);
  assert.equal(can(requests, [intake()], kind, true, false, true), false);
 }
});
test('workspace accepts only historical metadata and rejects current completion or authority claims', () => {
 assert.equal(nativeSettlementRequestMetadata([item(), { ...signed(), request_id: '0'.repeat(64) }], 'agreement').length, 2);
 for (const patch of [{ result_status: 'completed' }, { authorization_allowed: true }, { outcome_status: 'settled' }, { settlement_verified: true }, { observation: { type: 'signed', evidence: signed().observation.evidence } }, { signature_retention_key: 'caller-key' }]) {
  assert.throws(() => nativeSettlementRequestMetadata([{ ...item(), ...patch }], 'agreement'));
 }
 assert.throws(() => nativeSettlementRequestMetadata([item(), item()], 'agreement'));
});
