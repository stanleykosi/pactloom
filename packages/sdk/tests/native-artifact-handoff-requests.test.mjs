import {test} from 'node:test';
import assert from 'node:assert/strict';
import {WholepactClient,WholepactError} from '../dist/index.js';
const job='proof-'+'a'.repeat(64);
const view=()=>({schema_version:1,operation:'artifact_handoff',kind:'signer_review',proved_artifact_digest:'9'.repeat(64),request_id:'b'.repeat(64),agreement_id:'agreement',candidate_id:'candidate',manifest_digest:'c'.repeat(64),original_revision:7,queued_revision:8,attempt_revision:null,state:'queued',authorization_allowed:false,result_status:'unknown_not_financial_evidence',job_id:job,receipt_storage_key:'d'.repeat(64),receipt_digest:'e'.repeat(64),scope_digest:'f'.repeat(64),coordination_request_digest:'1'.repeat(64),handoff_status:'not_attempted'});
const json=v=>new Response(JSON.stringify(v),{headers:{'Content-Type':'application/json'}});
const session={session_token:'synthetic-session',csrf_token:'synthetic-csrf'};
test('native artifact handoff carries explicit kind and exact IDs without private material',async()=>{
 const calls=[];const client=new WholepactClient({token:'synthetic',fetch:async(url,options)=>{calls.push({url,options});return json(calls.length===1?session:view());}});
 await client.connect();await client.requestNativeArtifactHandoff('agreement',{candidate_id:'candidate',job_id:job,kind:'signer_review'},{expectedRevision:7,idempotencyKey:'original-native-handoff-key'});
 assert.equal(calls[1].url,'http://127.0.0.1:4318/v1/agreements/agreement/native-artifact-handoff-requests');assert.deepEqual(JSON.parse(calls[1].options.body),{candidate_id:'candidate',job_id:job,kind:'signer_review'});assert.equal(calls.length,2);
});
test('changed kind digest and financial approval claims never become successful handoff',async()=>{
 for(const patch of [{kind:'signature_intake'},{proved_artifact_digest:'short'},{handoff_status:'completed'},{authorization_allowed:true},{operation:'sign'}]){
 let calls=0;const client=new WholepactClient({token:'synthetic',fetch:async()=>json(++calls===1?session:{...view(),...patch})});await client.connect();await assert.rejects(client.requestNativeArtifactHandoff('agreement',{candidate_id:'candidate',job_id:job,kind:'signer_review'},{expectedRevision:7,idempotencyKey:'original-native-handoff-key'}),e=>e instanceof WholepactError&&e.code==='EXTERNAL_OUTCOME_UNCERTAIN');assert.equal(calls,2);
 }
});
test('started handoff remains unknown and withdrawal cannot claim cancellation',async()=>{
 let calls=0;const started={...view(),state:'attempt_started',attempt_revision:9,handoff_status:'attempted_outcome_unknown'};
 const client=new WholepactClient({token:'synthetic',fetch:async()=>json(++calls===1?session:started)});await client.connect();assert.equal((await client.nativeArtifactHandoffRequest('agreement',started.request_id)).handoff_status,'attempted_outcome_unknown');await assert.rejects(client.withdrawNativeArtifactHandoffRequest('agreement',started.request_id,{expectedRevision:9,idempotencyKey:'synthetic-withdraw-key'}),e=>e.code==='EXTERNAL_OUTCOME_UNCERTAIN');
});
