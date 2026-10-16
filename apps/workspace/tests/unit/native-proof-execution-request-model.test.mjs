import {test} from 'node:test';
import assert from 'node:assert/strict';
import {nativeProofExecutionRequestMetadata,canRequestProofExecution} from '../../src/native-proof-execution-request-model.ts';
const job='proof-'+'a'.repeat(64);
const item=()=>({schema_version:1,operation:'proof_execute',request_id:'b'.repeat(64),agreement_id:'agreement',candidate_id:'candidate',manifest_digest:'c'.repeat(64),original_revision:7,queued_revision:8,attempt_revision:null,state:'queued',authorization_allowed:false,result_status:'unknown_not_financial_evidence',job_id:job,receipt_storage_key:'d'.repeat(64),receipt_digest:'e'.repeat(64),scope_digest:'f'.repeat(64),coordination_request_digest:'1'.repeat(64),execution_status:'not_attempted',execution_operation_id:null});
test('proof views reject financial approval and wrong operation domains',()=>{
 assert.equal(nativeProofExecutionRequestMetadata([item()],'agreement').length,1);
 for(const patch of [{operation:'proof_run'},{job_id:'wrong'},{job_id:[job]},{state:'succeeded'},{authorization_allowed:true},{execution_status:'succeeded'}])assert.throws(()=>nativeProofExecutionRequestMetadata([{...item(),...patch}],'agreement'));
});
test('execution requests never replace a started attempt even after a durable outcome',()=>{
 assert.equal(canRequestProofExecution([], 'candidate', job,true,false,false),true);
 for(const value of [item(),{...item(),state:'attempt_started',attempt_revision:9,execution_status:'unknown'}])assert.equal(canRequestProofExecution([value],'candidate',job,true,false,false),false);
 const complete={...item(),state:'attempt_started',attempt_revision:9,execution_status:'durable_execution_recorded',execution_operation_id:'operation'};
 nativeProofExecutionRequestMetadata([complete],'agreement');assert.equal(canRequestProofExecution([complete],'candidate',job,true,false,false),false);
 assert.equal(canRequestProofExecution([complete],'candidate',job,true,false,true),false);
});
