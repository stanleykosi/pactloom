import { test } from 'node:test';
import assert from 'node:assert/strict';
import { WholepactClient, WholepactError, ownerInspectionMetadata } from '../dist/index.js';
const agreement='agreement-a'; const id='a'.repeat(64);
const request={ request_id:id, principal_id:'owner', agreement_id:agreement, candidate_id:'candidate-a', participant_id:'alice', manifest_digest:'b'.repeat(64) };
const queued=()=>({ schema_version:1, operation:'owner_account_inspection', request:{...request}, original_revision:4, queued_revision:5, attempt_revision:null, state:'queued', result_status:'unknown_no_committed_result', authorization_allowed:false, result:null });
const snapshot=()=>({ schema_version:1, request:{...request}, account_id:'account-a', source_principal_id:'local-owner-uid-1000', writer_epoch:1, recovery_required:false, inspected_at_ms:1000, provenance:'native_owner_approved_local_signer_journal', freshness:'historical_local_snapshot_no_live_witness_or_chain_observation', authorization_allowed:false, balance:null, account_pending_exposure:null, account_settled_debit:null, account_remaining_budget:null, authorizations:[], sponsor_policies:[], automation_grants:[] });
const historical=()=>({...queued(),state:'attempt_started',attempt_revision:6,result_status:'historical_native_approved_metadata',result:snapshot()});
const options={ expectedRevision:4,idempotencyKey:'exact-original-key' };
async function setup(result) {
 const calls=[]; const client=new WholepactClient({ token:'synthetic',fetch:async (url, options)=>{ calls.push({url,options}); return new Response(JSON.stringify(calls.length===1?{session_token:'synthetic-session',csrf_token:'synthetic-csrf'}:result)); }});
 await client.connect(); return {client,calls};
}
test('strict inspection metadata preserves historical results, unknown started state and no inferred zero',()=>{
 for(const v of [queued(),{...queued(),state:'withdrawn'},{...queued(),state:'attempt_started',attempt_revision:6},historical()]) assert.deepEqual(ownerInspectionMetadata([v],agreement),[v]);
 for(const field of ['balance','account_pending_exposure','account_settled_debit','account_remaining_budget']) { const v=historical();v.result[field]='0';assert.throws(()=>ownerInspectionMetadata([v],agreement)); }
 for(const patch of [{authorization_allowed:true},{freshness:'live'},{provenance:'browser_claim'},{inspected_at_ms:'1000'},{writer_epoch:0},{source_principal_id:null},{private_key:'secret'}]) { const v=historical();Object.assign(v.result,patch);assert.throws(()=>ownerInspectionMetadata([v],agreement)); }
 for(const patch of [{state:'completed'},{attempt_revision:6},{result_status:'settled'},{authorization_allowed:true},{original_revision:5},{approved:true}]) assert.throws(()=>ownerInspectionMetadata([{...queued(),...patch}],agreement));
 const wrong=historical();wrong.result.request.participant_id='bob';assert.throws(()=>ownerInspectionMetadata([wrong],agreement));
 assert.throws(()=>ownerInspectionMetadata([queued(),queued()],agreement));
});
test('exact scoped audit rows use integer amounts, explicit expiries and inert historical status',()=>{
 const v=historical(); v.result.authorizations=[{authorization_id:'a',original_consent_ref:'c'.repeat(64),proposal_id:'p',maximum_debit:'100',transaction_expiry_height:100,result_retained:false,latest_settlement_record:'canonical_consumed',automation_grant_id:'grant'}];
 v.result.sponsor_policies=[{policy_key:'d'.repeat(64),version:1,terms_digest:'e'.repeat(64),status:'paused',aggregate_budget:'1000',expires_at:null,witness_id:'w',witness_policy_digest:'f'.repeat(64)}];
 v.result.automation_grants=[{grant_id:'grant',application_id:'app',revision:1,terms_digest:'e'.repeat(64),status:'active',maximum_payment_debit:'100',maximum_outstanding_debit:'1000',expires_at_ms:2000}];
 assert.doesNotThrow(()=>ownerInspectionMetadata([v],agreement));
 for(const amount of [0,1.5,'01','0.1','2100000000000001']) { const bad=structuredClone(v);bad.result.authorizations[0].maximum_debit=amount;assert.throws(()=>ownerInspectionMetadata([bad],agreement)); }
 for(const label of ['settled','zero_exposure','live']) {const bad=structuredClone(v);bad.result.authorizations[0].latest_settlement_record=label;assert.throws(()=>ownerInspectionMetadata([bad],agreement));}
});
test('queue and exact-original retry use only candidate participant key and revision',async()=>{
 const {client,calls}=await setup(historical()); const input={candidate_id:'candidate-a',participant_id:'alice'};
 const result=await client.requestNativeAccountInspection(agreement,input,options);assert.equal(result.state,'attempt_started');
 assert.deepEqual(JSON.parse(calls[1].options.body),input); assert.equal(calls[1].options.headers.get('Idempotency-Key'),options.idempotencyKey);assert.equal(calls[1].options.headers.get('If-Match'),'"4"');
 await client.requestNativeAccountInspection(agreement,input,options);assert.equal(calls[2].options.body,calls[1].options.body);
});
test('caller-supplied account IDs, approval, result injection and invalid revision never leave the client',async()=>{
 const {client,calls}=await setup(queued());
 for(const field of ['account_id','approved','result','permission','balance']) await assert.rejects(client.requestNativeAccountInspection(agreement,{candidate_id:'candidate-a',participant_id:'alice',[field]:true},options));
 await assert.rejects(client.requestNativeAccountInspection(agreement,{candidate_id:'candidate-a',participant_id:'alice'},{...options,expectedRevision:0}));
 for(const bad of [null,undefined,[],42]) await assert.rejects(client.requestNativeAccountInspection(agreement,bad,options));
 for(const bad of [null,undefined,42,'short']) await assert.rejects(client.withdrawNativeAccountInspection(agreement,bad,options));
 await assert.rejects(client.nativeAccountInspectionRequests({toString:()=>agreement}));
 assert.equal(calls.length,1);
});
test('unbound mutation acknowledgement remains uncertain; reads enforce exact original identity',async()=>{
 const wrong=queued();wrong.request.participant_id='bob'; const {client}=await setup(wrong);
 await assert.rejects(client.requestNativeAccountInspection(agreement,{candidate_id:'candidate-a',participant_id:'alice'},options),e=>e instanceof WholepactError&&e.code==='EXTERNAL_OUTCOME_UNCERTAIN');
 await assert.rejects(client.nativeAccountInspectionRequest(agreement,'c'.repeat(64)),e=>e.code==='INVALID_RESPONSE');
});
