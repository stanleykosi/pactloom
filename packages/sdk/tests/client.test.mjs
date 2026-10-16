import { test } from 'node:test';
import assert from 'node:assert/strict';
import { WholepactClient, WholepactError } from '../dist/index.js';
const session = { schema_version:1,client_id:'synthetic-client',permissions:['read'],agreement_ids:[],all_agreements:true,session_token:'synthetic-session-token',csrf_token:'synthetic-csrf',expires_in_seconds:1800 };
const json = value => new Response(JSON.stringify(value), { headers:{'Content-Type':'application/json'} });
const key = 'test-idempotency-0001';
test('bootstrap is replaced by session token, and mutation carries exact retry/revision context', async () => {
  const calls=[];
  const client = new WholepactClient({token:'synthetic-bootstrap', fetch:async (url, options)=>{ calls.push({url,options}); return json(calls.length === 1 ? session : {}); }});
  await client.connect(); await client.mutate('/agreements/abc/intents', {amount:'200000001'}, {idempotencyKey:key,expectedRevision:4});
  assert.equal(calls[0].options.headers.get('Authorization'), 'Bearer synthetic-bootstrap');
  assert.equal(calls[1].options.headers.get('Authorization'), 'Bearer synthetic-session-token');
  assert.equal(calls[1].options.headers.get('X-Wholepact-CSRF'), session.csrf_token);
  assert.equal(calls[1].options.headers.get('If-Match'), '"4"');
  assert.equal(calls[1].options.headers.get('Idempotency-Key'),key);
  assert.equal(calls[1].options.redirect,'error');
  assert.equal(calls[1].options.credentials,'omit');
  assert.ok(calls[1].options.headers.get('X-Request-ID'));
  assert.ok(!calls[1].url.includes(session.session_token));
  client.disconnect(); await assert.rejects(client.capabilities(),/disconnected/);
});
test('local client rejects remote origins, credentials and query strings',()=>{
  for(const baseUrl of ['https://example.com/v1','http://127.0.0.1.evil.test/v1','http://x:y@localhost/v1','http://localhost/v1?token=a']) assert.throws(()=>new WholepactClient({baseUrl,token:'test'}));
});
test('malformed success or post-dispatch abort preserves external outcome uncertainty',async()=>{
  for (const fail of [() => new Response('{"broken":'), () => {throw new DOMException('Aborted','AbortError')}]) {
    let count=0; const client=new WholepactClient({token:'synthetic',fetch:async()=>++count===1?json(session):fail()}); await client.connect();
    await assert.rejects(client.mutate('/agreements',{}, {idempotencyKey:key}),error=>error instanceof WholepactError && error.code==='EXTERNAL_OUTCOME_UNCERTAIN' && error.details.idempotency_key===key);
  }
});
test('a proven pre-dispatch abort sends no mutation',async()=>{
  let count=0;const client=new WholepactClient({token:'synthetic',fetch:async()=>{count++;return json(session)}});await client.connect();const abort=new AbortController();abort.abort();
  await assert.rejects(client.mutate('/agreements',{}, {idempotencyKey:key,signal:abort.signal}),{name:'AbortError'});assert.equal(count,1);
});
test('SSE handles chunked frames and duplicate replay without putting auth in URL',async()=>{
  const events=[{event_id:'a',sequence:1,kind:'intent_recorded'},{event_id:'a',sequence:1,kind:'intent_recorded'},{event_id:'b',sequence:2,kind:'intent_withdrawn'}];
  const text=events.map(e=>`data: ${JSON.stringify(e)}\r\n\r\n`).join('');let observedUrl;
  const client=new WholepactClient({token:'synthetic',fetch:async(url,options)=>{observedUrl=url;assert.ok(options.headers.get('Authorization'));return new Response(new ReadableStream({start(controller){for(let i=0;i<text.length;i+=7)controller.enqueue(new TextEncoder().encode(text.slice(i,i+7)));controller.close()}}))}});
  const received=[];for await(const event of client.events())received.push(event.sequence);assert.deepEqual(received,[1,2]);assert.equal(observedUrl,'http://127.0.0.1:4318/v1/events?after=0');
});
test('native browser fetch is invoked with its global receiver',async()=>{
 let receiver;
 const client=new WholepactClient({token:'synthetic',fetch:async function(){receiver=this;return json(session)}});
 await client.connect();assert.equal(receiver,globalThis);
});
test('candidate methods share durable command semantics and never assert approval',async()=>{
  const calls=[];
  const client=new WholepactClient({token:'synthetic',fetch:async(url,options)=>{calls.push({url,options});return json(calls.length===1?session:{candidates:[]})}});
  await client.connect();
  const terms={manifest:{transaction_fee:'15000'},previous_candidate_id:null};
  await client.createCandidate('agreement-one',terms,{idempotencyKey:key,expectedRevision:3});
  await client.candidate('candidate-one');
  await client.reviewCandidate('candidate-one',{idempotencyKey:'test-review-candidate',expectedRevision:4});
  assert.equal(calls[1].url,'http://127.0.0.1:4318/v1/agreements/agreement-one/candidates');
  assert.equal(calls[1].options.headers.get('If-Match'),'"3"');
  assert.deepEqual(JSON.parse(calls[1].options.body),terms);
  assert.equal(calls[2].options.method,'GET');
  assert.equal(calls[3].url,'http://127.0.0.1:4318/v1/candidates/candidate-one/verify');
  assert.equal(calls[3].options.headers.get('If-Match'),'"4"');
  assert.deepEqual(JSON.parse(calls[3].options.body),{});
});

test('planning, recovery and cached job reads share the existing authenticated service contract',async()=>{
  const calls=[];
  const client=new WholepactClient({token:'synthetic',fetch:async(url,options)=>{calls.push({url,options});return json(calls.length===1?session:{})}});
  await client.connect();
  await client.selectRoster('agreement:one',{selected_intent_ids:['intent:alice']},{idempotencyKey:key,expectedRevision:12});
  await client.createProposal('agreement:one',{idempotencyKey:'terms-preview-key-0001',expectedRevision:13});
  await client.proposal('proposal:one');
  await client.reviewProposal('proposal:one',{idempotencyKey:'terms-review-key-0001',expectedRevision:14});
  await client.compareProposals('proposal:one','proposal:two');
  await client.candidateProofJobs('candidate:one');
  await client.recovery();
  assert.equal(calls[1].url,'http://127.0.0.1:4318/v1/agreements/agreement:one/roster-selection');
  assert.equal(calls[1].options.headers.get('If-Match'),'"12"');
  assert.deepEqual(JSON.parse(calls[1].options.body),{selected_intent_ids:['intent:alice']});
  assert.ok(calls[5].url.endsWith('/proposals/proposal:two/compare/proposal:one'));
  assert.ok(calls[6].url.endsWith('/candidates/candidate:one/proof-jobs'));
  assert.ok(calls[7].url.endsWith('/recovery'));
  for(const i of [3,5,6,7]){assert.equal(calls[i].options.method,'GET');assert.equal(calls[i].options.headers.has('X-Wholepact-CSRF'),false);}
});
test('resource identifiers reject path substitution but accept scoped colons and internal dots',async()=>{
  let calls=0;const client=new WholepactClient({token:'synthetic',fetch:async()=>{calls++;return json({})}});
  for(const id of ['..','.','x/y','x?token=secret','x%2Fy','http://evil',''])assert.throws(()=>client.agreement(id),/identifier/);
  assert.equal(calls,0);await client.agreement('scope:two..dots');assert.equal(calls,1);
});
test('a damaged mutation response preserves any server-provided operation identifier',async()=>{
  let calls=0;const client=new WholepactClient({token:'synthetic',fetch:async()=>++calls===1?json(session):new Response('{',{headers:{'x-operation-id':'operation-known-01'}})});await client.connect();
  await assert.rejects(client.createProposal('a',{idempotencyKey:key,expectedRevision:3}),error=>error.code==='EXTERNAL_OUTCOME_UNCERTAIN'&&error.operationId==='operation-known-01'&&error.details.expected_revision===3);
});
test('SSE control frames preserve session and storage failures instead of pretending to be events',async()=>{
  for(const [event,code] of [['session_expired','AUTHENTICATION_REQUIRED'],['service_unavailable','STORAGE_UNAVAILABLE']]){
    const client=new WholepactClient({token:'synthetic',fetch:async()=>new Response(`event: ${event}\ndata: {"code":"${code}"}\n\n`)});
    await assert.rejects(async()=>{for await(const ignored of client.events())assert.fail(JSON.stringify(ignored));},error=>error instanceof WholepactError&&error.code===code);
  }
});
test('candidate comparison addresses the exact immutable pair and starts no command',async()=>{
 let observed;const client=new WholepactClient({token:'synthetic',fetch:async(url,options)=>{observed={url,options};return json({signable:false,changes:[]})}});
 const comparison=await client.compareCandidates('older','newer');assert.equal(comparison.signable,false);assert.equal(observed.url,'http://127.0.0.1:4318/v1/candidates/newer/compare/older');assert.equal(observed.options.method,'GET');assert.equal(observed.options.headers.has('Idempotency-Key'),false);
});
test('sponsor policies keep private policy identity, immutable versions and read-only preview separate',async()=>{
 const calls=[];const client=new WholepactClient({token:'synthetic',fetch:async(url,options)=>{calls.push({url,options});return json(calls.length===1?session:{authorization_allowed:false})}});await client.connect();
 await client.sponsorPolicies('agreement');await client.sponsorPolicy('agreement','policy');
 await client.createSponsorPolicy('agreement',{policy_id:'policy',terms:{schema_version:1}},{idempotencyKey:key,expectedRevision:5});
 await client.updateSponsorPolicy('agreement',{policy_id:'policy',expected_policy_version:1,terms:{schema_version:1}},{idempotencyKey:'sponsor-version-0001',expectedRevision:6});
 await client.setSponsorPolicyState('agreement',{policy_id:'policy',expected_policy_version:2,state:'paused'},{idempotencyKey:'sponsor-state-key-01',expectedRevision:7});
 await client.previewSponsorPolicy('agreement','policy',{candidate_id:'candidate',expected_policy_version:2});
 assert.ok(calls[4].url.endsWith('/policy/versions'));assert.equal(calls[4].options.headers.get('If-Match'),'"6"');
 assert.ok(calls[5].url.endsWith('/policy/state'));assert.equal(JSON.parse(calls[5].options.body).state,'paused');
 assert.ok(calls[6].url.endsWith('/policy/preview'));assert.equal(calls[6].options.headers.has('Idempotency-Key'),false);assert.equal(calls[6].options.headers.has('If-Match'),false);assert.equal(calls[6].options.headers.get('X-Wholepact-CSRF'),'synthetic-csrf');
});
test('advanced sponsor editor preserves duplicate keys for authoritative rejection rather than normalizing them away',async()=>{
 const calls=[];const client=new WholepactClient({token:'synthetic',fetch:async(url,options)=>{calls.push({url,options});return json(calls.length===1?session:{})}});await client.connect();
 const source='{"schema_version":1,"schema_version":2,"maximum_match":"100000001"}';
 await client.saveSponsorPolicySource('agreement','policy',source,{idempotencyKey:key,expectedRevision:1});
 assert.equal(calls[1].options.body,`{"policy_id":"policy","terms":${source}}`);
 await client.saveSponsorPolicySource('agreement','policy',source,{idempotencyKey:key,expectedRevision:2},1);
 assert.equal(calls[2].options.body,`{"policy_id":"policy","expected_policy_version":1,"terms":${source}}`);
 assert.throws(()=>client.saveSponsorPolicySource('agreement','policy',' '.repeat(250001),{idempotencyKey:key}),/bounded editor/);
});
test('protected transport client sends only opaque handles and the original issued import identity',async()=>{
 const calls=[];const client=new WholepactClient({token:'synthetic',fetch:async(url,options)=>{calls.push({url,options});return json(calls.length===1?session:{})}});await client.connect();
 await client.stagedTransport('agreement');await client.transportPreview('agreement','opaque-handle');
 await client.importTransport('agreement','opaque-handle',{idempotencyKey:'original-issued-import-01',expectedRevision:9});
 assert.ok(calls[1].url.endsWith('/agreements/agreement/transport'));assert.ok(calls[2].url.endsWith('/transport/opaque-handle'));assert.ok(calls[3].url.endsWith('/transport/opaque-handle/import'));
 assert.deepEqual(JSON.parse(calls[3].options.body),{});assert.equal(calls[3].options.headers.get('If-Match'),'"9"');assert.equal(calls[3].options.headers.get('Idempotency-Key'),'original-issued-import-01');
 assert.equal(calls[3].options.body.includes('key'),false);assert.equal(calls[3].options.body.includes('ciphertext'),false);
});
test('a proven serialization failure is not mistaken for a possibly committed command',async()=>{
 let count=0;const client=new WholepactClient({token:'synthetic',fetch:async()=>{count++;return json(session)}});await client.connect();
 const cyclic={};cyclic.self=cyclic;await assert.rejects(client.mutate('/agreements',cyclic,{idempotencyKey:key}),TypeError);assert.equal(count,1);
});

test('pure POST validation and sponsor preview failures do not imply a committed mutation',async()=>{
 for(const method of ['validate','preview']){
  let count=0;const client=new WholepactClient({token:'synthetic',fetch:async()=>++count===1?json(session):Promise.reject(new Error('transport interrupted'))});await client.connect();
  await assert.rejects(method==='validate'?client.validateAgreement({}):client.previewSponsorPolicy('agreement','policy',{candidate_id:'candidate',expected_policy_version:1}),error=>error instanceof WholepactError&&error.code==='SERVICE_UNREACHABLE'&&error.retryable);
 }
});

test('record status reads keep scoped summaries and unknown account exposure explicit',async()=>{
 const status={status:'available',records:[],reason_code:null,account_exposure:'unknown_not_established_by_records'};let call;
 const client=new WholepactClient({token:'synthetic',fetch:async(url,options)=>{call={url,options};return json(status)}});
 assert.deepEqual(await client.records(),status);assert.ok(call.url.endsWith('/records'));assert.equal(call.options.method,'GET');assert.equal(call.options.headers.has('Idempotency-Key'),false);
});

test('received invitation inspection is read-only and requires no local agreement identity',async()=>{
 const calls=[];const client=new WholepactClient({token:'synthetic',fetch:async(url,options)=>{calls.push({url,options});return json({})}});
 await client.invitations();await client.invitation('opaque-invitation-handle');assert.ok(calls[0].url.endsWith('/invitations'));assert.ok(calls[1].url.endsWith('/invitations/opaque-invitation-handle'));
 for(const call of calls){assert.equal(call.options.method,'GET');assert.equal(call.options.body,undefined);assert.equal(call.options.headers.has('Idempotency-Key'),false);}
});
