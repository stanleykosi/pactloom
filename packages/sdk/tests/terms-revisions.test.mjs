import { test } from 'node:test';
import assert from 'node:assert/strict';
import { WholepactClient } from '../dist/index.js';
const session = { session_token: 'synthetic-session', csrf_token: 'synthetic-csrf' };
const draft = { schema_version:1,agreement_id:'synthetic-agreement',obligation_id:'synthetic-obligation',revision:2,purpose:'Synthetic revised terms',organizer_identity:'synthetic-organizer',network_profile_id:'zcash-testnet-unqualified',recipients:[{recipient_id:'recipient',address:'synthetic-not-a-payment-address',amount:'200000001',memo:null,instruction_provenance:'Synthetic only'}],funding_policy:{kind:'exact',target:'200000001'},fee_policy:{kind:'pro_rata'},privacy_profile:{mode:'local_only',proving_operator:null,dedicated_accounts_required:true},coordination_deadline:null,confirmation_policy:{required_confirmations:10},extensions:[] };
const options = { idempotencyKey:'synthetic-revise-key-0001',expectedRevision:7 };
const json = body => new Response(JSON.stringify(body), {headers:{'content-type':'application/json'}});
const result = () => ({agreement:structuredClone(draft),revision:8,terms_history:[{...draft,revision:1}],terms_editability:{allowed:true,reason:'Local unsigned draft only'}});
test('complete unsigned revision carries exact journal precondition independently of terms revision',async()=>{
 const calls=[];const client=new WholepactClient({token:'synthetic-bootstrap',fetch:async(url,init)=>{calls.push({url,init});return json(calls.length===1?session:result());}});
 await client.connect();const saved=await client.reviseAgreement(draft.agreement_id,draft,options);
 assert.equal(calls[1].url,'http://127.0.0.1:4318/v1/agreements/synthetic-agreement/terms-revisions');
 assert.equal(calls[1].init.headers.get('if-match'),'"7"');assert.equal(calls[1].init.headers.get('idempotency-key'),options.idempotencyKey);
 assert.equal(calls[1].init.body,JSON.stringify(draft));assert.equal(saved.agreement.revision,2);assert.equal(saved.revision,8);
 assert.equal(saved.terms_history[0].revision,1);
});
test('SDK requires a safe exact journal revision before dispatch and keeps path identifiers safe',()=>{
 let calls=0;const client=new WholepactClient({token:'synthetic',fetch:async()=>{calls++;return json({});}});
 for(const expectedRevision of [undefined,0,-1,1.5,Number.MAX_SAFE_INTEGER,Infinity])assert.throws(()=>client.reviseAgreement('agreement',draft,{...options,expectedRevision}),/exact positive journal revision/);
 assert.throws(()=>client.reviseAgreement('../agreement',draft,options),/identifier/);assert.equal(calls,0);
});
test('ambiguous, malformed and mismatched mutation successes cannot silently establish a save',async()=>{
 for(const reply of [null,{}, {...result(),agreement:{...draft,purpose:'substituted'}},{...result(),revision:9},{...result(),terms_editability:{allowed:'yes'}}]){
  let calls=0;const client=new WholepactClient({token:'synthetic',fetch:async()=>json(++calls===1?session:reply)});await client.connect();
  await assert.rejects(client.reviseAgreement(draft.agreement_id,draft,options),error=>error.code==='EXTERNAL_OUTCOME_UNCERTAIN'&&error.details.idempotency_key===options.idempotencyKey);
 }
});
test('original replay snapshot can omit optional editability without changing exact accepted revision',async()=>{
 let calls=0;const replay=result();delete replay.terms_editability;
 const client=new WholepactClient({token:'synthetic',fetch:async()=>json(++calls===1?session:replay)});await client.connect();
 const saved=await client.reviseAgreement(draft.agreement_id,draft,options);assert.equal(saved.revision,8);assert.equal(saved.terms_editability,undefined);
});
test('interrupted retry resends exact original complete terms and does not rebase journal revision',async()=>{
 const calls=[];const client=new WholepactClient({token:'synthetic',fetch:async(url,init)=>{calls.push({url,init});if(calls.length===2)throw new TypeError('synthetic lost response');return json(calls.length===1?session:result());}});await client.connect();
 await assert.rejects(client.reviseAgreement(draft.agreement_id,draft,options),{code:'EXTERNAL_OUTCOME_UNCERTAIN'});
 await client.reviseAgreement(draft.agreement_id,draft,options);
 assert.equal(calls[1].init.body,calls[2].init.body);for(const field of ['idempotency-key','if-match'])assert.equal(calls[1].init.headers.get(field),calls[2].init.headers.get(field));
});
test('stale journal and no-op errors retain authoritative service error codes without retrying',async()=>{
 for(const code of ['REVISION_CONFLICT','NO_TERMS_CHANGES','PERMISSION_DENIED']){
  let calls=0;const client=new WholepactClient({token:'synthetic',fetch:async()=>++calls===1?json(session):new Response(JSON.stringify({code,message:'Synthetic rejection',retryable:false}),{status:409})});await client.connect();
  await assert.rejects(client.reviseAgreement(draft.agreement_id,draft,options),error=>error.code===code);assert.equal(calls,2);
 }
});

test('dispatch snapshots exact body and command options before caller objects can change',async()=>{
 let finish;const delayed=new Promise(resolve=>{finish=resolve;});const calls=[];
 const client=new WholepactClient({token:'synthetic',fetch:async(url,init)=>{calls.push(init);return calls.length===1?json(session):delayed;}});await client.connect();
 const editable=structuredClone(draft),mutableOptions={...options};const save=client.reviseAgreement(draft.agreement_id,editable,mutableOptions);
 editable.purpose='Later caller mutation';mutableOptions.expectedRevision=99;mutableOptions.idempotencyKey='new-unrelated-retry-key';finish(json(result()));
 const saved=await save;assert.equal(saved.revision,8);assert.equal(JSON.parse(calls[1].body).purpose,draft.purpose);assert.equal(calls[1].headers.get('if-match'),'"7"');assert.equal(calls[1].headers.get('idempotency-key'),options.idempotencyKey);
});
