import { test } from 'node:test';
import assert from 'node:assert/strict';
import { WholepactClient, WholepactError } from '../dist/index.js';
const session={session_token:'synthetic-session',csrf_token:'synthetic-csrf'};
const json=value=>new Response(JSON.stringify(value),{headers:{'Content-Type':'application/json'}});
const job='proof-'+ 'a'.repeat(64);
const view=()=>({schema_version:1,operation:'proof_execute',request_id:'b'.repeat(64),agreement_id:'agreement',candidate_id:'candidate',manifest_digest:'c'.repeat(64),original_revision:7,queued_revision:8,attempt_revision:null,state:'queued',authorization_allowed:false,result_status:'unknown_not_financial_evidence',job_id:job,receipt_storage_key:'d'.repeat(64),receipt_digest:'e'.repeat(64),scope_digest:'f'.repeat(64),coordination_request_digest:'1'.repeat(64),execution_status:'not_attempted',execution_operation_id:null});
test('proof reconciliation sends exact existing IDs and never asks to run a prover',async()=>{
 const calls=[];const client=new WholepactClient({token:'synthetic',fetch:async(url,options)=>{calls.push({url,options});return json(calls.length===1?session:calls.length===3?[view()]:view());}});
 await client.connect();await client.requestNativeProofExecution('agreement',{candidate_id:'candidate',job_id:job},{idempotencyKey:'original-proof-request-key',expectedRevision:7});await client.nativeProofExecutionRequests('agreement');
 assert.equal(calls[1].url,'http://127.0.0.1:4318/v1/agreements/agreement/native-proof-execution-requests');
 assert.deepEqual(JSON.parse(calls[1].options.body),{candidate_id:'candidate',job_id:job});
 assert.equal(calls[1].options.headers.get('If-Match'),'"7"');assert.equal(calls[2].options.method,'GET');
});
test('wrong proof operation, job, scope or cached completion shape remains uncertain',async()=>{
 for(const patch of [{operation:'proof_run'},{job_id:'proof-'+'2'.repeat(64)},{receipt_digest:'short'},{execution_status:'durable_execution_recorded',execution_operation_id:null},{authorization_allowed:true}]){
  let count=0;const client=new WholepactClient({token:'synthetic',fetch:async()=>json(++count===1?session:{...view(),...patch})});await client.connect();
  await assert.rejects(client.requestNativeProofExecution('agreement',{candidate_id:'candidate',job_id:job},{idempotencyKey:'original-proof-request-key',expectedRevision:7}),e=>e instanceof WholepactError&&e.code==='EXTERNAL_OUTCOME_UNCERTAIN');assert.equal(count,2);
 }
});
test('lost proof request response never retries or substitutes a new key',async()=>{
 let count=0;const client=new WholepactClient({token:'synthetic',fetch:async()=>{if(++count===1)return json(session);throw new Error('lost');}});await client.connect();
 await assert.rejects(client.requestNativeProofExecution('agreement',{candidate_id:'candidate',job_id:job},{idempotencyKey:'original-proof-request-key',expectedRevision:7}),e=>e.code==='EXTERNAL_OUTCOME_UNCERTAIN');assert.equal(count,2);
});
test('withdrawal requires exact retained proof request identity',async()=>{
 let count=0;const client=new WholepactClient({token:'synthetic',fetch:async()=>json(++count===1?session:{...view(),state:'withdrawn'})});await client.connect();
 await client.withdrawNativeProofExecutionRequest('agreement','b'.repeat(64),{idempotencyKey:'original-proof-withdraw-key',expectedRevision:8});
});

test('proof status reads reject wrong identity, approval shapes and coerced job IDs',async()=>{
 for(const bad of [{...view(),agreement_id:'other'},{...view(),request_id:'f'.repeat(64)},{...view(),operation:'prove'},{...view(),authorization_allowed:true},{...view(),job_id:[job]}]) {
  let count=0;const client=new WholepactClient({token:'synthetic',fetch:async()=>json(++count===1?session:bad)});await client.connect();
  await assert.rejects(client.nativeProofExecutionRequest('agreement','b'.repeat(64)),e=>e.code==='INVALID_RESPONSE');
 }
 for(const bad of [view(),[view(),view()],[{...view(),job_id:[job]}],[{...view(),agreement_id:'other'}]]) {
  let count=0;const client=new WholepactClient({token:'synthetic',fetch:async()=>json(++count===1?session:bad)});await client.connect();
  await assert.rejects(client.nativeProofExecutionRequests('agreement'),e=>e.code==='INVALID_RESPONSE');
 }
});
