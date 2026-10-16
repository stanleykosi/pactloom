import { test } from 'node:test';
import assert from 'node:assert/strict';
import { nativeCommand, beginNativeCommand, finishNativeCommand, retryNativeCommand } from '../../src/native-request-session.ts';
test('inspection navigation preserves exact unknown command and repeated retry cannot race',()=>{
 const client={};const original={kind:'owner_inspection',candidate:'candidate-a',participantId:'alice',revision:5,key:'original-key'};
 assert.equal(beginNativeCommand(client,'agreement',original),true); finishNativeCommand(client,'agreement',original.key,false);
 assert.equal(beginNativeCommand(client,'agreement',{...original,key:'replacement'}),false);
 assert.equal(retryNativeCommand({},'agreement',original.key),null);assert.equal(retryNativeCommand(client,'agreement','different-key'),null);
 const retry=retryNativeCommand(client,'agreement',original.key);assert.deepEqual(retry,{...original,phase:'pending'});assert.equal(retryNativeCommand(client,'agreement',original.key),null);
 finishNativeCommand(client,'agreement','wrong-key',true);assert.equal(nativeCommand(client,'agreement').phase,'pending');
 finishNativeCommand(client,'agreement',original.key,true);assert.equal(nativeCommand(client,'agreement'),null);
});
test('withdrawal retries retain exact original request and never become native execution',()=>{
 const client={};const original={kind:'owner_inspection_withdraw',candidate:'candidate-a',participantId:'alice',requestId:'saved-original',revision:9,key:'withdraw-key'};
 beginNativeCommand(client,'agreement',original);finishNativeCommand(client,'agreement',original.key,false);
 assert.deepEqual(retryNativeCommand(client,'agreement',original.key),{...original,phase:'pending'});
 assert.equal(nativeCommand(client,'elsewhere'),null);
});

// Confirmed no-commit conflicts must not permanently freeze the shared command.
import { WholepactError } from '@wholepact/sdk';
import { inspectionRejectedBeforeCommit } from '../../src/account-inspection-outcome.ts';
test('only explicit service pre-commit rejections release an inspection command',()=>{
 for (const code of ['REVISION_CONFLICT','INVALID_TRANSITION']) {
  const client={};const original={kind:'owner_inspection',candidate:'candidate-a',participantId:'alice',revision:5,key:'rejected-key'};
  beginNativeCommand(client,'agreement',original);
  const error=new WholepactError({code,message:'rejected',retryable:false},409,'service-request');
  assert.equal(inspectionRejectedBeforeCommit(error),true);
  finishNativeCommand(client,'agreement',original.key,inspectionRejectedBeforeCommit(error));
  assert.equal(nativeCommand(client,'agreement'),null);
 }
 for (const error of [new Error('network'), {code:'REVISION_CONFLICT',status:409,requestId:'forged'},
  new WholepactError({code:'REVISION_CONFLICT',message:'unknown',retryable:false}),
  new WholepactError({code:'INVALID_TRANSITION',message:'unknown',retryable:false},409),
  new WholepactError({code:'EXTERNAL_OUTCOME_UNCERTAIN',message:'unknown',retryable:false},409,'request'),
  new WholepactError({code:'REVISION_CONFLICT',message:'unknown',retryable:false,operation_id:'operation'},409,'request'),
  new WholepactError({code:'REVISION_CONFLICT',message:'unknown',retryable:false},500,'request')]) {
   const client={};const original={kind:'owner_inspection_withdraw',candidate:'candidate-a',participantId:'alice',requestId:'original-request',revision:5,key:'original-key'};
   beginNativeCommand(client,'agreement',original);
   assert.equal(inspectionRejectedBeforeCommit(error),false);
   finishNativeCommand(client,'agreement',original.key,inspectionRejectedBeforeCommit(error));
   assert.deepEqual(nativeCommand(client,'agreement'),{...original,phase:'uncertain'});
 }
});
