import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { createHash } from 'node:crypto';
import { mkdtemp, readFile, readlink, writeFile, rm, mkdir } from 'node:fs/promises';
import { hostname, tmpdir } from 'node:os';
import { join, isAbsolute } from 'node:path';
import { WholepactClient, parseZec } from '../../dist/index.js';

// Opt-in actual SDK/service integration. No mocked backend, wallet, key or provider.
// Independently build and hash the service first; a matching hash alone is not source provenance.
// The one dropped-response case calls the service first, then deliberately discards
// its actual success response. It is explicit client-side fault injection.
const binary = process.env.WHOLEPACT_SERVICE_BINARY;
const expectedHash = process.env.WHOLEPACT_SERVICE_SHA256;
if (!binary || !isAbsolute(binary) || !/^[a-f0-9]{64}$/.test(expectedHash ?? '')) {
  throw new Error('Set WHOLEPACT_SERVICE_BINARY to a source-matched absolute binary path and WHOLEPACT_SERVICE_SHA256 to its independently recorded hash.');
}
const baseUrl = 'http://127.0.0.1:4318/v1';
const token = 'wholepact-development-only-not-a-secret';
const evidence = process.env.WHOLEPACT_ACCEPTANCE_REPORT_DIR;
if (evidence && !isAbsolute(evidence)) throw new Error('WHOLEPACT_ACCEPTANCE_REPORT_DIR must be an absolute output path.');
if (evidence) await mkdir(evidence, { recursive: true });
const temp = await mkdtemp(join(tmpdir(), 'wholepact-synthetic-metadata-'));
const database = join(temp, 'synthetic.sqlite');
const report = {scope:'Real SDK/service synthetic metadata integration; not browser or payment E2E', source_commit:process.env.WHOLEPACT_SOURCE_COMMIT ?? 'not supplied; establish build provenance separately', binary_sha256:expectedHash, cases:[], limits:['No browser DOM exercised','No native host invitation created or exported','No wallet, keys, proof, funds, chain provider or payment','Response-loss case is explicit fault injection after real service commit'], status:'running'};
let child; let serviceLog=''; let requestCount=0; let responseLoss=null; let completedResponseLoss=null; let spawnError;
const fetched = async (url,init) => { requestCount++; const response = await fetch(url,{...init,signal:AbortSignal.any([...(init.signal ? [init.signal] : []),AbortSignal.timeout(5000)])}); if(responseLoss && init.method==='POST' && url.endsWith(responseLoss)) { responseLoss=null; if(!response.ok)return response; await response.arrayBuffer(); completedResponseLoss={status:response.status,bodyConsumed:true}; throw new TypeError('Deliberate test-only loss of a real committed response'); } return response; };
const client = () => new WholepactClient({baseUrl,token,fetch:fetched});
const key = label => `joined-synthetic-${label}-0001`;
const pause = ms=>new Promise(r=>setTimeout(r,ms));
async function start(){
  const logStart=serviceLog.length; spawnError=undefined;
  child=spawn(binary,['--bind','127.0.0.1:4318','--database',database,'--development-fixture'],{stdio:['ignore','pipe','pipe']});
  child.on('error',error=>{spawnError=error;});
  child.stdout.on('data',x=>serviceLog+=x);child.stderr.on('data',x=>serviceLog+=x);
  for(let i=0;i<100;i++) {if(spawnError)throw spawnError;if(child.exitCode!==null||child.signalCode!==null) throw new Error(`Service exited ${child.exitCode}: ${serviceLog}`); if(serviceLog.slice(logStart).includes('local service listening')) return; await pause(50);}
  throw new Error('Service did not report listening within five seconds');
}
async function stop(){
  if(!child||spawnError||child.exitCode!==null||child.signalCode!==null)return;
  const p=child;
  p.kill('SIGINT');
  for(let i=0;i<100;i++){if(p.exitCode!==null||p.signalCode!==null)return;await pause(50);}
  p.kill('SIGTERM');
  for(let i=0;i<20;i++){if(p.exitCode!==null||p.signalCode!==null)throw new Error('Owned service needed SIGTERM after graceful shutdown timed out');await pause(50);}
  p.kill('SIGKILL');
  for(let i=0;i<20;i++){if(p.exitCode!==null||p.signalCode!==null)throw new Error('Owned service needed SIGKILL after shutdown timed out');await pause(50);}
  throw new Error('Owned service did not stop; temporary fixture retained for cleanup');
}
async function check(name,fn){const detail=await fn();report.cases.push({name,status:'passed',...(detail?{detail}:{})});console.log(`PASS ${name}`);}
async function reject(fn,expected){let caught;try{await fn();}catch(e){caught=e;}assert.ok(caught,'operation must reject');const code=typeof caught.code==='string'?caught.code:caught.name;if(expected)assert.equal(code,expected);return {code,status:caught.status??null};}
const original={schema_version:1,agreement_id:'synthetic-joined-agreement',obligation_id:'synthetic-joined-obligation',revision:1,purpose:'Synthetic local joint payment plan',organizer_identity:'synthetic-organizer',network_profile_id:'zcash-testnet-unqualified',recipients:[{recipient_id:'synthetic-recipient',address:'utestsyntheticneverforfunds',amount:'100000001',memo:null,instruction_provenance:'Synthetic unverified fixture only'}],funding_policy:{kind:'exact',target:'100000001'},fee_policy:{kind:'pro_rata'},privacy_profile:{mode:'local_only',proving_operator:null,dedicated_accounts_required:true},coordination_deadline:null,confirmation_policy:{required_confirmations:10},extensions:[]};
let c,view,revised,committedIntentView;
const durableView = ({terms_editability:currentEligibility,...durable}) => durable;
try{
 await check('Configured service binary matches its independently recorded hash',async()=>{
  assert.equal(createHash('sha256').update(await readFile(binary)).digest('hex'),expectedHash);
  return {hostname:hostname(),network_namespace:await readlink('/proc/self/ns/net').catch(()=> 'not exposed on this platform')};
 });
 await start();c=client();
 await check('Real bootstrap session, read capability and empty durable inventory',async()=>{const s=await c.connect();assert.ok(s.permissions.includes('propose'));assert.ok(s.permissions.includes('intent'));const caps=await c.capabilities();assert.equal(caps.features.local_agreements.api_access,'local_http');assert.equal(caps.features.local_agreements.status,'supported');assert.deepEqual(await c.agreements(),[]);return {permissions:s.permissions,local_agreements:caps.features.local_agreements};});
 await check('Eleven malformed amount inputs rejected before dispatch',async()=>{const count=requestCount;for(const amount of ['1e8','1,2',' 1','1 ','-1','+1','.2','01','1.','0.000000001','NaN'])assert.throws(()=>parseZec(amount));assert.equal(parseZec('1.00000001'),'100000001');assert.equal(requestCount,count);});
 await check('Cancelled pre-dispatch draft changes no durable state',async()=>{const signal=AbortSignal.abort();const count=requestCount;await reject(()=>c.createAgreement(original,{idempotencyKey:key('aborted'),signal}),'AbortError');assert.equal(requestCount,count);assert.deepEqual(await c.agreements(),[]);});
 await check('Invalid exact funding, empty purpose and unsafe IDs rejected by actual service',async()=>{const rejected=[];for(const bad of [{...original,purpose:''},{...original,funding_policy:{kind:'exact',target:'2'}},{...original,organizer_identity:'../invalid'}])rejected.push(await reject(()=>c.createAgreement(bad,{idempotencyKey:key(`invalid-${rejected.length}`)}),['INVALID_TERMS','CONSERVATION_FAILURE','INVALID_TERMS'][rejected.length]));assert.deepEqual(await c.agreements(),[]);return rejected;});
 await check('Concurrent exact local draft dispatch and replay never duplicate',async()=>{
  const repeated=await Promise.all([c.createAgreement(original,{idempotencyKey:key('create')}),c.createAgreement(original,{idempotencyKey:key('create')})]);
  assert.deepEqual(durableView(repeated[0]),durableView(repeated[1]));
  view=await c.agreement(original.agreement_id);
  assert.deepEqual(view.agreement,original);
  assert.deepEqual(durableView(repeated[0]),durableView(view));
  const replay=await c.createAgreement(original,{idempotencyKey:key('create')});
  assert.deepEqual(replay,durableView(view));
  assert.equal((await c.agreements()).length,1);assert.equal(view.terms_editability.allowed,true);
  return {journal_revision:view.revision,exposure:view.authorization_exposure,chain:view.chain_observation};
 });
 await check('Same mutation key with altered payload is rejected',async()=>{const result=await reject(()=>c.createAgreement({...original,purpose:'Substituted terms'},{idempotencyKey:key('create')}),'IDEMPOTENCY_CONFLICT');assert.deepEqual((await c.agreement(original.agreement_id)).agreement,original);return result;});
 await check('Immutable exact terms revision retains original history',async()=>{revised={...structuredClone(original),revision:2,purpose:'Synthetic revised exact terms',recipients:[{...original.recipients[0],amount:'200000001'}],funding_policy:{kind:'exact',target:'200000001'}};view=await c.reviseAgreement(original.agreement_id,revised,{idempotencyKey:key('revise'),expectedRevision:view.revision});assert.deepEqual(view.agreement,revised);assert.deepEqual(view.terms_history.find(t=>t.revision===1),original);return {journal_revision:view.revision,terms_revision:view.agreement.revision};});
 await check('Stale terms revision rejected without rebasing',async()=>{const before=await c.agreement(original.agreement_id);const result=await reject(()=>c.reviseAgreement(original.agreement_id,{...revised,revision:3,purpose:'Stale attempt'},{idempotencyKey:key('stale'),expectedRevision:1}),'REVISION_CONFLICT');assert.deepEqual(await c.agreement(original.agreement_id),before);return result;});
 const intent={intent_id:'synthetic-intent-one',agreement_id:original.agreement_id,participant_id:'synthetic-contributor',desired_contribution:'100000001',maximum_net_debit:'100006001',fee_cap:'6000',conditions:['Synthetic plan only; no funds reserved'],valid_until:null,status:'active'};
 await check('Invalid contribution bound rejected by service',async()=>{const before=await c.agreement(original.agreement_id);const result=await reject(()=>c.recordIntent(original.agreement_id,{...intent,maximum_net_debit:'1'},{idempotencyKey:key('bad-intent'),expectedRevision:view.revision}),'DEBIT_CAP_EXCEEDED');assert.deepEqual(await c.agreement(original.agreement_id),before);return result;});
 const intentRevision=view.revision;
 await check('Lost response after actual committed intent is reported uncertain',async()=>{
  responseLoss=`/agreements/${original.agreement_id}/intents`;completedResponseLoss=null;
  const error=await reject(()=>c.recordIntent(original.agreement_id,intent,{idempotencyKey:key('intent'),expectedRevision:intentRevision}),'EXTERNAL_OUTCOME_UNCERTAIN');
  assert.ok(completedResponseLoss?.bodyConsumed,'the deliberate discard must actually consume a real successful response');
  assert.ok(completedResponseLoss.status>=200&&completedResponseLoss.status<300);
  committedIntentView=await c.agreement(original.agreement_id);
  assert.deepEqual(committedIntentView.intents,[intent]);assert.equal(committedIntentView.revision,intentRevision+1);
  return {...error,fault:'real success response deliberately discarded after body consumption',discarded_status:completedResponseLoss.status};
 });
 await check('Service restart invalidates sessions and retains exact intent for original replay',async()=>{
  await stop();serviceLog+='\n--- RESTART SAME TEMPORARY METADATA DATABASE ---\n';await start();
  await reject(()=>c.agreements(),'AUTHENTICATION_REQUIRED');c.disconnect();c=client();await c.connect();
  // Read BEFORE retry: replay must not conceal a lost durable intent or original revision.
  const retained=await c.agreement(original.agreement_id);
  assert.deepEqual(retained,committedIntentView);assert.deepEqual(retained.intents,[intent]);
  assert.equal(retained.revision,intentRevision+1);assert.equal(retained.terms_editability.allowed,false);
  view=await c.recordIntent(original.agreement_id,intent,{idempotencyKey:key('intent'),expectedRevision:intentRevision});
  assert.equal(view.revision,retained.revision);assert.deepEqual(view.intents,retained.intents);
  assert.deepEqual(await c.agreement(original.agreement_id),retained);
  return {journal_revision:view.revision,terms_revision:view.agreement.revision,verified_retained_before_replay:true};
 });
 await check('Post-participation term rewrite rejected without erasing exact terms',async()=>{const result=await reject(()=>c.reviseAgreement(original.agreement_id,{...revised,revision:3,purpose:'Illegitimate rewrite'},{idempotencyKey:key('sealed-terms'),expectedRevision:view.revision}),'INVALID_TRANSITION');assert.deepEqual((await c.agreement(original.agreement_id)).agreement,revised);return result;});
 await check('Protected invitation read boundary cannot fabricate readiness',async()=>{
  return {invitation_list:await reject(()=>c.invitations(),'UNSUPPORTED_CAPABILITY'),agreement_transport:await reject(()=>c.stagedTransport(original.agreement_id),'UNSUPPORTED_CAPABILITY')};
 });
 await check('Freeze terms and exact review stay explicitly non-signable',async()=>{view=await c.createProposal(original.agreement_id,{idempotencyKey:key('proposal'),expectedRevision:view.revision});const p=view.proposals.at(-1);assert.equal(p.status,'terms_only_not_signable');assert.equal(p.artifact_digest,null);assert.equal(p.effects_commitment,null);view=await c.reviewProposal(p.proposal_id,{idempotencyKey:key('review'),expectedRevision:view.revision});const review=view.verification_reports.at(-1);assert.equal(review.review_summary.signable,false);assert.equal(review.status,'unsupported');return {proposal_status:p.status,review_status:review.status,scope:review.review_summary.scope};});
 await check('Withdraw plan retains history and cancellation never asserts settlement safety',async()=>{view=await c.withdrawIntent(original.agreement_id,intent.intent_id,{idempotencyKey:key('withdraw'),expectedRevision:view.revision});assert.equal(view.intents[0].status,'withdrawn');const prior={exposure:view.authorization_exposure,chain:view.chain_observation};view=await c.requestCancellation(original.agreement_id,{idempotencyKey:key('cancel'),expectedRevision:view.revision});assert.equal(view.cancellation_requested,true);assert.equal(view.authorization_exposure,prior.exposure);assert.equal(view.chain_observation,prior.chain);return {journal_revision:view.revision,...prior};});
 await check('Reconnect preserves cancelled plan, original terms and exact review history',async()=>{const before=await c.agreement(original.agreement_id);await c.endSession();await assert.rejects(()=>c.agreements(),/disconnected/);c=client();await c.connect();assert.deepEqual(await c.agreement(original.agreement_id),before);await reject(()=>c.authorizations(),'UNSUPPORTED_CAPABILITY');await reject(()=>c.accounts(),'UNSUPPORTED_CAPABILITY');await c.endSession();});
 report.status='passed';
}catch(error){report.status='failed';report.failure={name:error.name,code:error.code??null,message:error.message};console.error(`${error.name}: ${error.message}`);process.exitCode=1;}
finally{try{await stop();}catch(e){report.cleanup_error=e.message;report.status='failed';process.exitCode=1;}const stopped=!child||spawnError||child.exitCode!==null||child.signalCode!==null;if(stopped)await rm(temp,{recursive:true,force:true});report.temporary_fixture_removed=Boolean(stopped);report.actual_http_requests=requestCount;report.finished_at=new Date().toISOString();if(evidence){await writeFile(join(evidence,'joined-client-service.result.json'),JSON.stringify(report,null,2)+'\n');await writeFile(join(evidence,'joined-client-service.server.log'),serviceLog);}console.log(JSON.stringify({status:report.status,passed:report.cases.length,requests:requestCount,temporary_fixture_removed:report.temporary_fixture_removed}));}
