import { test } from 'node:test';
import assert from 'node:assert/strict';
import { WholepactClient, WholepactError } from '../dist/index.js';
const session = { session_token: 'synthetic-session', csrf_token: 'synthetic-csrf' };
const json = value => new Response(JSON.stringify(value), { headers: { 'Content-Type': 'application/json' } });
test('native request only carries candidate and exact original retry context', async () => {
  const calls=[];
  const client=new WholepactClient({token:'synthetic-bootstrap',fetch:async(url,options)=>{calls.push({url,options});return json(calls.length===1?session:{schema_version:1,request_id:"a".repeat(64),agreement_id:"agreement:one",candidate_id:"candidate:one",manifest_digest:"b".repeat(64),original_revision:7,queued_revision:8,attempt_revision:null,state:"queued",authorization_allowed:false,result_status:"unknown_not_financial_evidence"});}});
  await client.connect();
  await client.requestNativeConstruction('agreement:one',{candidate_id:'candidate:one'},{idempotencyKey:'original-native-request-key',expectedRevision:7});
  await client.nativeRequests('agreement:one');
  await client.nativeRequest('agreement:one','request:one');
  assert.equal(calls[1].url,'http://127.0.0.1:4318/v1/agreements/agreement:one/native-requests');
  assert.deepEqual(JSON.parse(calls[1].options.body),{candidate_id:'candidate:one'});
  assert.equal(calls[1].options.headers.get('If-Match'),'"7"');
  assert.equal(calls[1].options.headers.get('Idempotency-Key'),'original-native-request-key');
  assert.equal(calls[2].options.method,'GET');assert.equal(calls[3].options.method,'GET');
});
test('native request requires explicit revision before dispatch', async () => {
  let calls=0;const client=new WholepactClient({token:'synthetic',fetch:async()=>{calls++;return json(session);}});
  await client.connect();
  assert.throws(()=>client.requestNativeConstruction('agreement',{candidate_id:'candidate'},{idempotencyKey:'original-native-request-key'}),/revision/);
  assert.equal(calls,1);
});
test('lost native request response is uncertain and never automatically retried', async () => {
  let calls=0;const client=new WholepactClient({token:'synthetic',fetch:async()=>{if(++calls===1)return json(session);throw new Error('interrupted');}});
  await client.connect();
  await assert.rejects(client.requestNativeConstruction('agreement',{candidate_id:'candidate'},{idempotencyKey:'original-native-request-key',expectedRevision:7}),e=>e instanceof WholepactError&&e.code==='EXTERNAL_OUTCOME_UNCERTAIN');
  assert.equal(calls,2);
});

test('malformed or substituted native mutation response is uncertain, never success', async () => {
  for (const value of [[], {}, {schema_version:1,state:'signed',authorization_allowed:true}]) {
    let calls=0; const client=new WholepactClient({token:'synthetic',fetch:async()=>json(++calls===1?session:value)});
    await client.connect();
    await assert.rejects(client.requestNativeConstruction('agreement',{candidate_id:'candidate'},{idempotencyKey:'original-native-request-key',expectedRevision:7}),e=>e instanceof WholepactError&&e.code==='EXTERNAL_OUTCOME_UNCERTAIN');
    assert.equal(calls,2);
  }
});
