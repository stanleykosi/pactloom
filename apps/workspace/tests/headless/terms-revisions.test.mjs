/** Synthetic browser-route qualification. No HTTP listener or live provider is started. */
import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { resolve } from 'node:path';
import { chromium } from 'playwright';
let browser;
before(async()=>{browser=await chromium.launch({headless:true,executablePath:process.env.CHROMIUM_PATH??'/usr/bin/chromium',args:['--no-sandbox','--disable-background-networking']});});
after(async()=>{await browser?.close();});
const original = () => ({schema_version:1,agreement_id:'synthetic-edit-agreement',obligation_id:'synthetic-obligation',revision:1,purpose:'Synthetic original draft',organizer_identity:'synthetic-organizer',network_profile_id:'zcash-testnet-unqualified',recipients:[{recipient_id:'synthetic-recipient',address:'synthetic-original-address',amount:'200000001',memo:'Synthetic reference',instruction_provenance:'Synthetic instructions only'}],funding_policy:{kind:'exact',target:'200000001'},fee_policy:{kind:'pro_rata'},privacy_profile:{mode:'local_only',proving_operator:null,dedicated_accounts_required:true},coordination_deadline:null,confirmation_policy:{required_confirmations:10},extensions:[]});
async function fixture({uncertain=false,holdSave=false,holdValidation=false,allowed=true,postCommit500=false}={}){
 const context=await browser.newContext();const page=await context.newPage();const errors=[];page.on('pageerror',error=>errors.push(error.message));
 let view={agreement:original(),revision:7,cancellation_requested:false,progress:'draft',authorization_exposure:'unknown',chain_observation:'unknown',intents:[],terms_history:[],terms_editability:{allowed,reason:allowed?'Local unsigned draft is editable.':'Participation already exists; editing is unavailable.'}};
 const mutations=[],validations=[];let attempts=0;let saved=null;let releaseSave,releaseValidation;const saveGate=new Promise(resolve=>{releaseSave=resolve;});const validationGate=new Promise(resolve=>{releaseValidation=resolve;});
 await context.route('**/*',async route=>{
  const request=route.request();const url=new URL(request.url());
  const json=(value,status=200)=>route.fulfill({status,contentType:'application/json',body:JSON.stringify(value),headers:{'Access-Control-Allow-Origin':'http://127.0.0.1:4319'}});
  if(url.origin==='http://127.0.0.1:4319'){
   const path=url.pathname==='/'?'index.html':url.pathname.slice(1);if(path!=='index.html'&&!/^assets\/[A-Za-z0-9_.-]+$/.test(path))return route.abort();
   const body=await readFile(resolve('dist',path));return route.fulfill({body,contentType:path.endsWith('.js')?'application/javascript':path.endsWith('.css')?'text/css':'text/html'});
  }
  if(url.origin!=='http://127.0.0.1:4318')return route.abort();
  if(request.method()==='OPTIONS')return route.fulfill({status:204,headers:{'Access-Control-Allow-Origin':'http://127.0.0.1:4319','Access-Control-Allow-Headers':'Authorization,Content-Type,X-Wholepact-CSRF,Idempotency-Key,If-Match,X-Request-ID','Access-Control-Allow-Methods':'GET,POST,OPTIONS'}});
  const path=url.pathname.slice(3);
  if(path==='/session')return json({session_token:'synthetic-session',csrf_token:'synthetic-csrf',client_id:'synthetic-client',permissions:['read','propose','intent','coordinate'],all_agreements:true,agreement_ids:[]});
  if(path==='/capabilities')return json({api_version:'v1',engine_version:'synthetic',features:{},profiles:[],adapters:[],limits:{},runtime:{storage:'local_metadata_unencrypted'}});
  if(path==='/agreements'&&request.method()==='GET')return json([view]);
  if(path==='/agreements/synthetic-edit-agreement'&&request.method()==='GET')return json(view);
  if(path==='/events')return route.fulfill({contentType:'text/event-stream',body:': synthetic fixture\n\n'});
  if(['/authorizations','/accounts'].includes(path))return json([]);
  if(path==='/records')return json({status:'unavailable',records:null,reason_code:'PARTICIPANT_RECORD_RUNTIME_NOT_CONNECTED',account_exposure:'unknown_not_established_by_records'});
  if(path==='/agreements/validate'){
   validations.push(request.postDataJSON());if(holdValidation)await validationGate;return json({valid:true});
  }
  if(path.endsWith('/terms-revisions')){
   const body=request.postDataJSON();mutations.push({body:request.postData(),headers:request.headers()});attempts++;
   if(!saved){view={...view,agreement:body,revision:8,terms_history:[view.agreement]};saved=structuredClone(view);delete saved.terms_editability;}
   if(holdSave&&attempts===1)await saveGate;
   if(postCommit500&&attempts===1)return json({code:'STORAGE_UNAVAILABLE',message:'Synthetic post-commit metadata failure',retryable:false},500);
   if(uncertain&&attempts===1)return route.fulfill({contentType:'application/json',body:'{'});
   if(uncertain&&attempts===2)return json({code:'PERMISSION_DENIED',message:'Synthetic temporary permission rejection',retryable:false},403);
   return json(saved);
  }
  return json({code:'UNSUPPORTED_CAPABILITY',message:'Synthetic fixture endpoint unavailable',retryable:false},501);
 });
 await page.goto('http://127.0.0.1:4319/');await page.getByLabel('Session bootstrap token').fill('synthetic-bootstrap');await page.getByRole('button',{name:'Open local workspace',exact:true}).click();await page.getByRole('button',{name:/Synthetic original draft/}).click();
 return {context,page,mutations,validations,errors,releaseSave,releaseValidation,changeJournal:()=>{view={...view,revision:view.revision+1};}};
}
async function review(page){await page.getByRole('button',{name:'Edit unsigned terms',exact:true}).click();await page.getByLabel('Purpose',{exact:true}).fill('Synthetic revised draft');await page.getByLabel('Recipient 1 amount (ZEC)',{exact:true}).fill('2.00000002');await page.getByRole('button',{name:'Review exact changes',exact:true}).click();await page.getByRole('checkbox').waitFor();}
async function expectDisabled(locator,value=true){assert.equal(await locator.isDisabled(),value);}
async function waitText(page,text){await page.getByText(text,{exact:true}).waitFor();}

test('review dismiss/reopen and back clear consent; save appends once with distinct terms and journal revisions',async()=>{
 const f=await fixture();const {page}=f;
 try{
  await review(page);const save=page.getByRole('button',{name:'Save terms revision 2',exact:true});await expectDisabled(save);assert.equal(await page.getByRole('checkbox').isChecked(),false);
  const dialog=page.getByRole('dialog');assert.match(await dialog.textContent(),/200000001/);assert.match(await dialog.textContent(),/200000002/);
  await page.getByRole('checkbox').check();await page.getByRole('button',{name:'Back to editing',exact:true}).click();await page.getByRole('button',{name:'Review exact changes',exact:true}).click();await expectDisabled(save);assert.equal(await page.getByRole('checkbox').isChecked(),false);
  await page.getByRole('checkbox').check();await page.keyboard.press('Escape');await page.getByRole('button',{name:'Edit unsigned terms',exact:true}).click();assert.equal(await page.getByLabel('Purpose',{exact:true}).inputValue(),'Synthetic original draft');assert.equal(await page.getByRole('checkbox').count(),0);await page.getByRole('button',{name:'Cancel',exact:true}).click();
  await review(page);await page.getByRole('checkbox').check();await save.click();await page.getByRole('heading',{name:'Synthetic revised draft',exact:true}).waitFor();
  assert.equal(f.mutations.length,1);assert.equal(JSON.parse(f.mutations[0].body).revision,2);assert.equal(f.mutations[0].headers['if-match'],'"7"');
  await waitText(page,'Terms revision 2 · journal revision 8');await page.getByText('Terms revision 1 · Synthetic original draft',{exact:true}).click();assert.match(await page.getByRole('main').textContent(),/synthetic-original-address/);
  assert.deepEqual(await page.evaluate(()=>[localStorage.length,sessionStorage.length]),[0,0]);assert.deepEqual(f.errors,[]);
 }finally{await f.context.close();}
});

test('in-flight dismissal and late uncertainty retain exact body/key/revision across reopen and permission rejection',async()=>{
 const f=await fixture({uncertain:true,holdSave:true});const {page}=f;
 try{
  await review(page);await page.getByRole('checkbox').check();await page.getByRole('button',{name:'Save terms revision 2',exact:true}).click();await waitText(page,'The original save is in progress');await page.keyboard.press('Escape');
  await page.getByRole('button',{name:'Resume original terms revision',exact:true}).click();await waitText(page,'The original save is in progress');await expectDisabled(page.getByRole('button',{name:'Saving original revision…',exact:true}));f.releaseSave();await waitText(page,'The original save outcome is uncertain');
  await page.getByRole('button',{name:'Close editor',exact:true}).click();await page.getByRole('button',{name:'Refresh workspace',exact:true}).click();await page.getByRole('heading',{name:'Synthetic revised draft',exact:true}).waitFor();await page.getByRole('button',{name:'Resume original terms revision',exact:true}).click();
  await page.getByRole('button',{name:'Retry exact original revision',exact:true}).click();await page.getByRole('alert').filter({hasText:'PERMISSION_DENIED'}).waitFor();await waitText(page,'The original save outcome is uncertain');
  await page.keyboard.press('Escape');await page.getByRole('button',{name:'Resume original terms revision',exact:true}).click();await page.getByRole('button',{name:'Retry exact original revision',exact:true}).click();await page.getByRole('dialog').waitFor({state:'hidden'});
  assert.equal(f.mutations.length,3);for(const attempt of f.mutations){assert.equal(attempt.body,f.mutations[0].body);assert.equal(attempt.headers['idempotency-key'],f.mutations[0].headers['idempotency-key']);assert.equal(attempt.headers['if-match'],'"7"');}
  assert.equal(f.validations.length,1);assert.deepEqual(await page.evaluate(()=>[localStorage.length,sessionStorage.length]),[0,0]);assert.deepEqual(f.errors,[]);
 }finally{f.releaseSave();await f.context.close();}
});

test('closing an unfinished validation cannot resurrect reviewed terms on reopen',async()=>{
 const f=await fixture({holdValidation:true});const {page}=f;
 try{
  await page.getByRole('button',{name:'Edit unsigned terms',exact:true}).click();await page.getByLabel('Purpose',{exact:true}).fill('Synthetic discarded edit');await page.getByRole('button',{name:'Review exact changes',exact:true}).click();await page.getByRole('button',{name:'Validating terms…',exact:true}).waitFor();await page.keyboard.press('Escape');
  await page.getByRole('button',{name:'Edit unsigned terms',exact:true}).click();f.releaseValidation();await page.waitForTimeout(100);assert.equal(await page.getByLabel('Purpose',{exact:true}).inputValue(),'Synthetic original draft');assert.equal(await page.getByRole('checkbox').count(),0);assert.equal(f.mutations.length,0);
 }finally{f.releaseValidation();await f.context.close();}
});

test('stale journal invalidates review and consent; denied eligibility exposes reason',async()=>{
 const f=await fixture();try{
  await review(f.page);await f.page.getByRole('checkbox').check();f.changeJournal();await f.page.getByRole('button',{name:'Refresh workspace',exact:true}).evaluate(button=>button.click());await waitText(f.page,'New terms revision unavailable');assert.equal(await f.page.getByRole('checkbox').count(),0);await expectDisabled(f.page.getByRole('button',{name:'Review exact changes',exact:true}));await f.page.keyboard.press('Escape');await f.page.getByRole('button',{name:'Edit unsigned terms',exact:true}).click();assert.equal(await f.page.getByRole('checkbox').count(),0);assert.equal(f.mutations.length,0);
 }finally{await f.context.close();}
 const blocked=await fixture({allowed:false});try{await expectDisabled(blocked.page.getByRole('button',{name:'Edit unsigned terms',exact:true}));await waitText(blocked.page,'Participation already exists; editing is unavailable.');assert.equal(blocked.mutations.length,0);}finally{await blocked.context.close();}
});

test('JSON 500 after commit retains exact request for reopened retry',async()=>{
 const f=await fixture({postCommit500:true});try{
  await review(f.page);await f.page.getByRole('checkbox').check();await f.page.getByRole('button',{name:'Save terms revision 2',exact:true}).click();await waitText(f.page,'The original save outcome is uncertain');
  await f.page.keyboard.press('Escape');await f.page.getByRole('button',{name:'Resume original terms revision',exact:true}).click();await f.page.getByRole('button',{name:'Retry exact original revision',exact:true}).click();await f.page.getByRole('dialog').waitFor({state:'hidden'});
  assert.equal(f.mutations.length,2);assert.equal(f.mutations[0].body,f.mutations[1].body);assert.equal(f.mutations[0].headers['idempotency-key'],f.mutations[1].headers['idempotency-key']);assert.equal(f.mutations[1].headers['if-match'],'"7"');
 }finally{await f.context.close();}
});
