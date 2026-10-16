import { test } from 'node:test';
import assert from 'node:assert/strict';
import { visibleRecordSummaries, observedSettlementCount } from '../../src/record-model.ts';
test('missing or incompatible record status cannot become a known empty exposure view',()=>{
 for(const value of [null,[],{status:'unavailable',records:null},{status:'available',records:[],account_exposure:'zero'}])assert.equal(visibleRecordSummaries(value),null);
 assert.deepEqual(visibleRecordSummaries({status:'available',records:[],account_exposure:'unknown_not_established_by_records'}),[]);
});
test('settlement display excludes stale, contradictory, reorganized and recovery-required summaries',()=>{
 const records=['no_observation','stale','contradictory','reorganized','included','confirmation_policy_met'].map(confidence=>({confidence,recovery_required:false}));
 assert.equal(observedSettlementCount(records),1);records.at(-1).recovery_required=true;assert.equal(observedSettlementCount(records),0);
});
