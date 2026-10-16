import { test } from 'node:test';
import assert from 'node:assert/strict';
import { draftAvailability, invitationAvailability, paymentNextAction } from '../../src/payment-journey-model.ts';
const supported = { features: { local_agreements: { status: 'supported', operations: ['create'] }, protected_transport_runtime: { status: 'experimental', api_access: 'local_http' } } };
const unsigned = { progress: 'gathering_intent', cancellation_requested: false, authorization_exposure: 'not_authorized', chain_observation: 'not_submitted' };
test('new draft guidance requires actual capability, permission and fresh service read', () => {
  assert.equal(draftAvailability(supported, ['propose'], false).allowed, true);
  for (const api_access of ['embedded_only', 'unavailable', 'local_http_request_only']) assert.equal(draftAvailability({ features: { local_agreements: { status: 'supported', operations: ['create'], api_access } } }, ['propose'], false).allowed, false);
  assert.equal(draftAvailability({ features: { local_agreements: { status: 'supported', operations: ['create'], api_access: 'local_http' } } }, ['propose'], false).allowed, true);
  for (const [cap, permission, stale] of [[null, ['propose'], false], [supported, [], false], [supported, ['propose'], true], [{ features: { local_agreements: { status: 'supported' } } }, ['propose'], false]]) assert.equal(draftAvailability(cap, permission, stale).allowed, false);
});
test('readable transport never claims invitation creation and ignores contradictory or missing capabilities', () => {
  assert.equal(invitationAvailability(supported, false).readable, true);
  for (const cap of [null, { features: {} }, { features: { protected_transport_runtime: { status: 'unavailable', api_access: 'local_http' } } }, { features: { protected_transport_runtime: { status: 'supported', api_access: 'embedded_only' } } }]) assert.equal(invitationAvailability(cap, false).readable, false);
  assert.equal(invitationAvailability(supported, true).readable, false);
});
test('unknown, released and consumed exposure cannot advance into a fresh payment step', () => {
  for (const authorization_exposure of ['unknown', 'authorized_locally', 'released', 'outstanding_uncertain', 'expired_observed', 'conflicted_observed', 'consumed', 'future_state']) {
    const next = paymentNextAction({ ...unsigned, authorization_exposure }, false);
    assert.equal(next.action, 'status'); assert.equal(next.title, 'Check what may still spend');
  }
});
test('staleness, cancellation and chain uncertainty take priority over optimistic progress', () => {
  const ready = { ...unsigned, progress: 'ready_for_submission' };
  assert.equal(paymentNextAction(ready, true).title, 'Refresh before continuing');
  assert.equal(paymentNextAction({ ...ready, cancellation_requested: true }, false).title, 'Keep checking any shared approvals');
  for (const chain_observation of ['submission_unknown', 'reorganized', 'conflicted_observed', 'backend_rejected']) assert.equal(paymentNextAction({ ...ready, chain_observation }, false).title, 'Resolve the original payment’s status');
  for (const chain_observation of ['unknown', 'pending_observed', 'included', 'confirmation_policy_met', 'expired_observed', 'future_state']) assert.equal(paymentNextAction({ ...ready, chain_observation }, false).action, 'status');
  assert.equal(paymentNextAction(ready, false).title, 'Inspect the recorded stage');
});
test('only clean unsigned planning offers review and review is never authorization', () => {
  assert.deepEqual(paymentNextAction(unsigned, false).action, 'review');
  for (const progress of ['validation_failed', 'requires_revision', 'declined', 'obsolete']) assert.equal(paymentNextAction({ ...unsigned, progress }, false).title, 'Review the terms before going further');
  for (const progress of ['closed', 'cancellation_requested', 'cancel_requested']) assert.equal(paymentNextAction({ ...unsigned, progress }, false).action, 'status');
});
