import { test } from 'node:test';
import assert from 'node:assert/strict';
import { WholepactClient } from '@wholepact/sdk';
import { beginPlanningCommand, currentPlanningResolution, dismissPlanningResolution, dispatchPlanningCommand, intentScope, planningSnapshot, retryPlanningCommand, subscribePlanning } from '../../src/planning-command-session.ts';
const draft=()=>({schema_version:1,agreement_id:'synthetic-plan',obligation_id:'synthetic-obligation',revision:1,purpose:'Synthetic unchanged purpose',organizer_identity:'synthetic-owner',network_profile_id:'zcash-testnet-unqualified',recipients:[{recipient_id:'synthetic-recipient',address:'synthetic-never-funded',amount:'100000001',memo:null,instruction_provenance:'Synthetic only'}],funding_policy:{kind:'exact',target:'100000001'},fee_policy:{kind:'pro_rata'},privacy_profile:{mode:'local_only',proving_operator:null,dedicated_accounts_required:true},coordination_deadline:null,confirmation_policy:{required_confirmations:10},extensions:[]});
const intent=()=>({intent_id:'synthetic-intent',agreement_id:'synthetic-plan',participant_id:'synthetic-person',desired_contribution:'100000000',maximum_net_debit:'100001000',fee_cap:'1000',conditions:[],valid_until:null,status:'active'});
const view=(revision=1,intents=[])=>({agreement:draft(),revision,intents,cancellation_requested:false,progress:'draft',authorization_exposure:'unknown',chain_observation:'unknown'});
const input=kind=>kind==='draft'?{kind,draft:draft(),key:'synthetic-original-draft'}:{kind,intent:intent(),revision:7,key:'synthetic-original-intent'};
async function fixture(kind,first='loss',hold=false){
 const calls=[];let saved;let release;const gate=new Promise(resolve=>release=resolve);
 const client=new WholepactClient({token:'synthetic-public-bootstrap',fetch:async(url,options)=>{
  if(String(url).endsWith('/session'))return Response.json({session_token:'synthetic-session',csrf_token:'synthetic-csrf'});
  calls.push({url:String(url),body:options.body,headers:Object.fromEntries(new Headers(options.headers))});
  const submitted=JSON.parse(options.body);
  if(!saved)saved=kind==='draft'?{...view(),agreement:submitted}:view(8,[submitted]);
  if(calls.length===1){if(hold)await gate;if(first==='loss')throw new Error('Synthetic successful-response loss');if(first==='500')return Response.json({code:'STORAGE_UNAVAILABLE',message:'Synthetic post-commit failure'}, {status:500});if(first==='malformed')return new Response('{',{status:200});if(first==='substitution')return Response.json({...saved,agreement:{...saved.agreement,purpose:'Substituted'}});if(first==='intent-substitution')return Response.json({...saved,intents:[{...submitted,maximum_net_debit:'200000000'}]});if(first==='wrong-revision')return Response.json({...saved,revision:999});if(first==='duplicate-intent')return Response.json({...saved,intents:[submitted,submitted]});}
  return Response.json(saved);
 }});await client.connect();return {client,calls,release,saved:()=>saved};
}
for(const kind of ['draft','intent'])for(const failure of ['loss','500','malformed','wrong-revision'])test(`${kind}: ${failure} retains exact request through dismiss/reopen and explicit retry`,async()=>{
 const f=await fixture(kind,failure,true), originalInput=input(kind), scope=kind==='draft'?'draft':intentScope('synthetic-plan');let notifications=0;
 const unmount=subscribePlanning(f.client,scope,()=>notifications++);const original=beginPlanningCommand(f.client,originalInput);const sent=dispatchPlanningCommand(f.client,original);unmount();
 assert.equal(planningSnapshot(f.client,scope).command,original);assert.equal(beginPlanningCommand(f.client,input(kind)),null);assert.equal(retryPlanningCommand(f.client,scope),null);
 if(kind==='draft')originalInput.draft.purpose='Edited after dispatch';else originalInput.intent.maximum_net_debit='999999999';
 assert.equal(f.calls.length,1);f.release();await assert.rejects(sent);const reopened=planningSnapshot(f.client,scope).command;
 assert.equal(reopened.phase,'uncertain');assert.equal(reopened.encoded,original.encoded);assert.equal(reopened.key,original.key);assert.equal(reopened.revision,original.revision);
 const remount=subscribePlanning(f.client,scope,()=>notifications++);assert.equal(f.calls.length,1,'observation/remount never retries');
 const retry=retryPlanningCommand(f.client,scope);await dispatchPlanningCommand(f.client,retry);remount();
 assert.equal(f.calls.length,2);assert.equal(f.calls[0].body,f.calls[1].body);assert.equal(f.calls[0].headers['idempotency-key'],f.calls[1].headers['idempotency-key']);assert.equal(f.calls[0].headers['if-match'],f.calls[1].headers['if-match']);
 assert.equal(planningSnapshot(f.client,scope).command,null);assert.deepEqual(planningSnapshot(f.client,scope).resolution,{key:original.key,kind,agreementId:'synthetic-plan',...(kind==='intent'?{intentId:'synthetic-intent'}:{}),journalRevision:kind==='draft'?1:8,outcome:'saved'});assert.equal(notifications,3);
});
test('exact acknowledgement rejects substituted draft and intent bodies and duplicate intent identities',async()=>{
 for(const [kind,failure] of [['draft','substitution'],['intent','intent-substitution'],['intent','duplicate-intent']]){const f=await fixture(kind,failure), command=beginPlanningCommand(f.client,input(kind));await assert.rejects(dispatchPlanningCommand(f.client,command));assert.equal(planningSnapshot(f.client,command.scope).command.phase,'uncertain');}
});
test('a first known pre-commit 4xx clears; unknown errors and a later 4xx cannot erase uncertainty',async()=>{
 for(const [status,code,expected] of [[422,'INVALID_TERMS','rejected'],[409,'REVISION_CONFLICT','rejected'],[403,'PERMISSION_DENIED','rejected'],[400,'UNRECOGNIZED_ERROR','uncertain'],[500,'INVALID_TERMS','uncertain'],[0,'INVALID_TERMS','uncertain']]){
  const client={createAgreement:async()=>{throw {status,code};},recordIntent:async()=>{throw {status,code};}};const command=beginPlanningCommand(client,input('draft'));await assert.rejects(dispatchPlanningCommand(client,command));const state=planningSnapshot(client,'draft');assert.equal(state.command?.phase??state.resolution.outcome,expected);if(expected==='rejected')assert.equal(state.resolution.journalRevision,null);
 }
 const client={createAgreement:async()=>{throw {status:500,code:'STORAGE_UNAVAILABLE'};},recordIntent:async()=>{}};
 const original=beginPlanningCommand(client,input('draft'));await assert.rejects(dispatchPlanningCommand(client,original));client.createAgreement=async()=>{throw {status:403,code:'PERMISSION_DENIED'};};
 const retry=retryPlanningCommand(client,'draft');await assert.rejects(dispatchPlanningCommand(client,retry));assert.equal(planningSnapshot(client,'draft').command.phase,'uncertain');assert.equal(planningSnapshot(client,'draft').command.key,original.key);
});
test('cancel before submission is inert; new sessions and agreement scopes cannot inherit another request',()=>{
 const a={},b={};const scope=intentScope('synthetic-plan');let notified=0;const cancel=subscribePlanning(a,scope,()=>notified++);cancel();assert.equal(planningSnapshot(a,scope).command,null);assert.equal(notified,0);
 const command=beginPlanningCommand(a,input('intent'));assert.equal(planningSnapshot(b,scope).command,null);assert.equal(planningSnapshot(a,intentScope('different-plan')).command,null);assert.equal(planningSnapshot(a,'draft').command,null);assert.equal(retryPlanningCommand(b,scope),null);assert.equal(planningSnapshot(a,scope).command,command);
});
test('double dispatch and stale completion handles cannot issue another request or clear original state',async()=>{
 const f=await fixture('draft','loss',true), command=beginPlanningCommand(f.client,input('draft'));const first=dispatchPlanningCommand(f.client,command);await assert.rejects(dispatchPlanningCommand(f.client,command));assert.equal(f.calls.length,1);f.release();await assert.rejects(first);
 await assert.rejects(dispatchPlanningCommand(f.client,command));assert.equal(f.calls.length,1);assert.equal(planningSnapshot(f.client,'draft').command.phase,'uncertain');
 const retry=retryPlanningCommand(f.client,'draft');await dispatchPlanningCommand(f.client,retry);await assert.rejects(dispatchPlanningCommand(f.client,retry));assert.equal(f.calls.length,2);assert.equal(planningSnapshot(f.client,'draft').resolution.outcome,'saved');
});
test('successful completion after dismissal remains discoverable without inventing another request',async()=>{
 const f=await fixture('intent','success',true);const command=beginPlanningCommand(f.client,input('intent'));const result=dispatchPlanningCommand(f.client,command);f.release();await result;const reopened=planningSnapshot(f.client,command.scope);assert.equal(reopened.command,null);assert.deepEqual(reopened.resolution,{key:command.key,kind:'intent',agreementId:'synthetic-plan',intentId:'synthetic-intent',journalRevision:8,outcome:'saved'});assert.equal(f.calls.length,1);
});

test('completed-before-reopen confirmation is scoped and stale dismiss/view handlers cannot consume later state',async()=>{
 const f=await fixture('draft','success');const first=beginPlanningCommand(f.client,input('draft'));await dispatchPlanningCommand(f.client,first);
 const notice=planningSnapshot(f.client,'draft').resolution;assert.equal(currentPlanningResolution(f.client,'draft',notice),true);assert.equal(currentPlanningResolution({},'draft',notice),false);assert.equal(currentPlanningResolution(f.client,intentScope('synthetic-plan'),notice),false);
 const next=beginPlanningCommand(f.client,{...input('draft'),key:'synthetic-next-draft'});assert.ok(next,'confirmed result does not block a new deliberate draft');assert.equal(currentPlanningResolution(f.client,'draft',notice),false);assert.equal(dismissPlanningResolution(f.client,'draft',notice),false);assert.equal(planningSnapshot(f.client,'draft').command,next);
 await dispatchPlanningCommand(f.client,next);const latest=planningSnapshot(f.client,'draft').resolution;assert.equal(dismissPlanningResolution(f.client,'draft',notice),false);assert.equal(planningSnapshot(f.client,'draft').resolution,latest);assert.equal(dismissPlanningResolution(f.client,'draft',latest),true);assert.equal(planningSnapshot(f.client,'draft').resolution,null);assert.equal(f.calls.length,2);
});
