import { test } from 'node:test';
import assert from 'node:assert/strict';
import { nativeCommand, nativeCommandVersion, subscribeNativeCommand, beginNativeCommand, finishNativeCommand } from '../../src/native-request-session.ts';
const request = {kind:'enqueue',candidate:'candidate',revision:7,key:'exact-browser-enqueue-key'};
test('unmount and remount preserve an in-flight request and late uncertain outcome', async()=>{
 const client={};let first=0;let second=0;
 const unmount=subscribeNativeCommand(client,'agreement',()=>first++);
 assert.equal(beginNativeCommand(client,'agreement',request),true);unmount();
 const remount=subscribeNativeCommand(client,'agreement',()=>second++);
 assert.equal(nativeCommand(client,'agreement').phase,'pending');
 assert.equal(beginNativeCommand(client,'agreement',{...request,key:'replacement-key'}),false);
 await Promise.resolve();finishNativeCommand(client,'agreement',request.key,false);
 assert.equal(nativeCommand(client,'agreement').phase,'uncertain');
 assert.equal(nativeCommand(client,'agreement').key,request.key);assert.equal(first,1);assert.equal(second,1);remount();
});
test('withdrawal keeps exact operation kind and request ID across navigation',()=>{
 const client={};const command={...request,kind:'withdraw',requestId:'exact-native-request'};
 beginNativeCommand(client,'agreement',command);
 finishNativeCommand(client,'agreement',command.key,false);
 assert.equal(nativeCommand(client,'agreement').kind,'withdraw');
 assert.equal(nativeCommand(client,'agreement').requestId,'exact-native-request');
 finishNativeCommand(client,'agreement','another-key',true);
 assert.equal(nativeCommand(client,'agreement').phase,'uncertain');
 finishNativeCommand(client,'agreement',command.key,true);
 assert.equal(nativeCommand(client,'agreement'),null);
});
test('request state is isolated by authenticated client and agreement',()=>{
 const client={},other={};beginNativeCommand(client,'agreement',request);
 assert.equal(nativeCommand(other,'agreement'),null);assert.equal(nativeCommand(client,'different'),null);
});

test('late completion invalidates previously read inventory even when command returns to null',()=>{
 const client={};const originalVersion=nativeCommandVersion(client,'agreement');
 beginNativeCommand(client,'agreement',request);
 assert.notEqual(nativeCommandVersion(client,'agreement'),originalVersion);
 const pendingVersion=nativeCommandVersion(client,'agreement');
 finishNativeCommand(client,'agreement',request.key,true);
 assert.equal(nativeCommand(client,'agreement'),null);
 assert.notEqual(nativeCommandVersion(client,'agreement'),originalVersion);
 assert.notEqual(nativeCommandVersion(client,'agreement'),pendingVersion);
});

test('proof request kinds retain exact jobs across navigation and exclude construction in both directions',()=>{
 for(const kind of ['proof_reconcile','proof_withdraw']) {
  const client={};const proof={kind,candidate:'candidate',jobId:'proof-'+ 'a'.repeat(64),revision:9,key:`original-${kind}`,requestId:kind==='proof_withdraw'?'original-request':undefined};
  const unsubscribe=subscribeNativeCommand(client,'agreement',()=>{});
  assert.equal(beginNativeCommand(client,'agreement',proof),true);unsubscribe();
  assert.equal(beginNativeCommand(client,'agreement',request),false);
  finishNativeCommand(client,'agreement',proof.key,false);
  assert.deepEqual(nativeCommand(client,'agreement'),{...proof,phase:'uncertain'});
  assert.equal(beginNativeCommand(client,'agreement',{...proof,key:'replacement'}),false);
  finishNativeCommand(client,'agreement','another-key',true);
  assert.equal(nativeCommand(client,'agreement').phase,'uncertain');
  const previous=nativeCommandVersion(client,'agreement');
  finishNativeCommand(client,'agreement',proof.key,true);
  assert.ok(nativeCommandVersion(client,'agreement')>previous);
  assert.equal(beginNativeCommand(client,'agreement',request),true);
  assert.equal(beginNativeCommand(client,'agreement',proof),false);
 }
});

test('settlement command keeps exact intake and kind through navigation and blocks other native commands', () => {
 for (const kind of ['settlement_handoff', 'settlement_withdraw']) {
  const client = {};
  const settlement = { kind, candidate: 'candidate', jobId: 'proof-' + 'a'.repeat(64), intakeRequestId: 'b'.repeat(64), settlementKind: 'transaction_checkpoint', revision: 9, key: `original-${kind}-command-key`, requestId: kind === 'settlement_withdraw' ? 'c'.repeat(64) : undefined };
  const unmount = subscribeNativeCommand(client, 'agreement', () => {});
  assert.equal(beginNativeCommand(client, 'agreement', settlement), true); unmount();
  assert.equal(beginNativeCommand(client, 'agreement', request), false);
  finishNativeCommand(client, 'agreement', settlement.key, false);
  assert.deepEqual(nativeCommand(client, 'agreement'), { ...settlement, phase: 'uncertain' });
  assert.equal(beginNativeCommand(client, 'agreement', { ...settlement, key: 'replacement-command-key' }), false);
  finishNativeCommand(client, 'agreement', 'wrong-key', true);
  assert.equal(nativeCommand(client, 'agreement').phase, 'uncertain');
  const before = nativeCommandVersion(client, 'agreement');
  finishNativeCommand(client, 'agreement', settlement.key, true);
  assert.ok(nativeCommandVersion(client, 'agreement') > before);
  assert.equal(beginNativeCommand(client, 'agreement', request), true);
  assert.equal(beginNativeCommand(client, 'agreement', settlement), false);
 }
});

test('dispatch queue and withdrawal preserve the exact transaction identity through remount and uncertainty', () => {
 for (const kind of ['submission_dispatch', 'dispatch_withdraw']) {
  const client = {}; const command = { kind, candidate: 'synthetic-candidate', jobId: 'proof-' + 'a'.repeat(64), intakeRequestId: 'b'.repeat(64), transactionRequestId: 'c'.repeat(64), revision: 10, key: `original-${kind}-command`, requestId: kind === 'dispatch_withdraw' ? 'd'.repeat(64) : undefined };
  const unsubscribe = subscribeNativeCommand(client, 'agreement', () => {});
  assert.equal(beginNativeCommand(client, 'agreement', command), true); unsubscribe();
  const remount = subscribeNativeCommand(client, 'agreement', () => {});
  for (const otherKind of ['enqueue', 'proof_reconcile', 'proof_execute', 'artifact_handoff', 'settlement_handoff', 'submission_dispatch']) assert.equal(beginNativeCommand(client, 'agreement', { ...request, kind: otherKind }), false);
  finishNativeCommand(client, 'agreement', command.key, false);
  assert.deepEqual(nativeCommand(client, 'agreement'), { ...command, phase: 'uncertain' });
  assert.equal(nativeCommand(client, 'agreement').transactionRequestId, command.transactionRequestId);
  assert.equal(beginNativeCommand(client, 'agreement', { ...command, key: 'replacement-command-key' }), false);
  finishNativeCommand(client, 'agreement', 'wrong-command-key', true);
  assert.equal(nativeCommand(client, 'agreement').phase, 'uncertain');
  const version = nativeCommandVersion(client, 'agreement');
  finishNativeCommand(client, 'agreement', command.key, true);
  assert.ok(nativeCommandVersion(client, 'agreement') > version);
  assert.equal(beginNativeCommand(client, 'agreement', request), true);
  assert.equal(beginNativeCommand(client, 'agreement', command), false);
  assert.equal(nativeCommand({}, 'agreement'), null);
  assert.equal(nativeCommand(client, 'other-agreement'), null);
  remount();
 }
});

test('reconciliation commands retain exact kind, dispatch and private record selectors through remount and uncertainty', () => {
 for (const kind of ['settlement_reconciliation', 'reconciliation_withdraw']) for (const reconciliationKind of ['provider_observation', 'independent_record_resolution']) {
  const client = {}; const command = { kind, reconciliationKind, candidate: 'synthetic-candidate', dispatchRequestId: 'a'.repeat(64), transactionRequestId: 'b'.repeat(64), revision: 12, key: `original-${kind}-${reconciliationKind}`, requestId: kind === 'reconciliation_withdraw' ? 'c'.repeat(64) : undefined,
   participantId: reconciliationKind === 'independent_record_resolution' ? 'synthetic-participant' : undefined, recordId: reconciliationKind === 'independent_record_resolution' ? 'synthetic-record' : undefined };
  const unmount = subscribeNativeCommand(client, 'agreement', () => {});
  assert.equal(beginNativeCommand(client, 'agreement', command), true); unmount();
  const remount = subscribeNativeCommand(client, 'agreement', () => {});
  for (const otherKind of ['enqueue', 'proof_reconcile', 'proof_execute', 'artifact_handoff', 'settlement_handoff', 'submission_dispatch', 'settlement_reconciliation']) assert.equal(beginNativeCommand(client, 'agreement', { ...request, kind: otherKind }), false);
  finishNativeCommand(client, 'agreement', command.key, false);
  assert.deepEqual(nativeCommand(client, 'agreement'), { ...command, phase: 'uncertain' });
  assert.equal(beginNativeCommand(client, 'agreement', { ...command, key: 'distinct-unacknowledged-replacement' }), false);
  // Pure metadata parsing and status reads have no transition that can clear this latch.
  const before = nativeCommandVersion(client, 'agreement');
  finishNativeCommand(client, 'agreement', 'wrong-key', true);
  assert.equal(nativeCommandVersion(client, 'agreement'), before); assert.equal(nativeCommand(client, 'agreement').phase, 'uncertain');
  finishNativeCommand(client, 'agreement', command.key, true);
  assert.ok(nativeCommandVersion(client, 'agreement') > before); assert.equal(nativeCommand(client, 'agreement'), null);
  assert.equal(beginNativeCommand(client, 'agreement', request), true); assert.equal(beginNativeCommand(client, 'agreement', command), false);
  assert.equal(nativeCommand({}, 'agreement'), null); assert.equal(nativeCommand(client, 'other-agreement'), null); remount();
 }
});
