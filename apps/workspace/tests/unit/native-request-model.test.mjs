import { test } from 'node:test';
import assert from 'node:assert/strict';
import { nativeRequestMetadata, canRequestNativeConstruction } from '../../src/native-request-model.ts';
const item = () => ({schema_version:1,request_id:'a'.repeat(64),agreement_id:'a',candidate_id:'c',manifest_digest:'b'.repeat(64),original_revision:4,queued_revision:5,attempt_revision:null,state:'queued',authorization_allowed:false,result_status:'unknown_not_financial_evidence'});
test('native request metadata refuses success claims and unknown state',()=>{
  assert.equal(nativeRequestMetadata([item()],'a').length,1);
  for(const patch of [{state:'signed'},{authorization_allowed:true},{result_status:'succeeded'},{agreement_id:'other'},{queued_revision:9},{attempt_revision:6}]) assert.throws(()=>nativeRequestMetadata([{...item(),...patch}],'a'));
});
test('native request controls preserve uncertain and existing attempts',()=>{
  assert.equal(canRequestNativeConstruction([], 'c',true,false,false),true);
  for(const requests of [null,[item()],[{...item(),state:'attempt_started',attempt_revision:6}]]) assert.equal(canRequestNativeConstruction(requests,'c',true,false,false),false);
  assert.equal(canRequestNativeConstruction([],'c',true,false,true),false);
  assert.equal(canRequestNativeConstruction([],'c',false,false,false),false);
  assert.equal(canRequestNativeConstruction([{...item(),state:'withdrawn'}],'c',true,false,false),true);
});
