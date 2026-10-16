import { test } from 'node:test';
import assert from 'node:assert/strict';
import { beginTermsCommand, finishTermsCommand, retryTermsCommand, subscribeTermsCommand, termsCommand, termsContextChanged, termsDifferences, termsReview, freshTermsEditor, termsEditorReducer, termsSaveFailure, sameTermsSession, proposalTermsContext, proposalReportAppliesToCurrentTerms } from '../../src/terms-revision-model.ts';
const draft={agreement_id:'synthetic-agreement',revision:3,purpose:'Before',recipients:[{recipient_id:'one',address:'synthetic-before',amount:'200000001',memo:null,instruction_provenance:'Synthetic only'}],funding_policy:{kind:'exact',target:'200000001'},fee_policy:{kind:'pro_rata'},coordination_deadline:null,confirmation_policy:{required_confirmations:10},extensions:[]};
const opening={agreement:draft,revision:9,terms_editability:{allowed:true,reason:'Local draft'}};
const after={...draft,revision:4,purpose:'After',recipients:[{...draft.recipients[0],address:'synthetic-after',amount:'200000002'}],funding_policy:{kind:'exact',target:'200000002'}};
test('review captures independent immutable before and after snapshots, exact amounts and journal revision',()=>{
 const review=termsReview(opening,after);const differences=termsDifferences(review.before,review.after);
 assert.equal(review.journalRevision,9);assert.equal(review.after.revision,4);assert.equal(differences.length,3);
 assert.ok(differences.find(item=>item.field==='Recipients').before.includes('200000001'));
 assert.ok(differences.find(item=>item.field==='Recipients').after.includes('200000002'));
 review.after.purpose='tampered local copy';assert.equal(after.purpose,'After');assert.equal(JSON.parse(review.encoded).purpose,'After');
});
test('journal changes, terms substitutions and missing or denied eligibility invalidate review',()=>{
 assert.equal(termsContextChanged(opening,structuredClone(opening)),false);
 for(const current of [{...opening,revision:10},{...opening,agreement:after},{...opening,terms_editability:undefined},{...opening,terms_editability:{allowed:false,reason:'Participation exists'}}])assert.equal(termsContextChanged(opening,current),true);
});
test('dismiss and reopen retain exact pending body and late uncertain outcome and disallow replacement',()=>{
 const client={};const review=termsReview(opening,after);let seen=0;
 const dismiss=subscribeTermsCommand(client,draft.agreement_id,()=>seen++);
 const original=beginTermsCommand(client,review,'synthetic-original-key');dismiss();
 assert.equal(termsCommand(client,draft.agreement_id).phase,'pending');assert.equal(beginTermsCommand(client,review,'replacement-key'),null);
 const reopen=subscribeTermsCommand(client,draft.agreement_id,()=>seen++);
 finishTermsCommand(client,draft.agreement_id,original.key,'uncertain');assert.equal(termsCommand(client,draft.agreement_id).phase,'uncertain');
 const retry=retryTermsCommand(client,draft.agreement_id);assert.equal(retry.encoded,original.encoded);assert.equal(retry.key,original.key);assert.equal(retry.revision,9);
 assert.equal(retryTermsCommand(client,draft.agreement_id),null);assert.equal(seen,3);reopen();
});
test('only original completion clears request; client and agreement boundaries are isolated',()=>{
 const client={};const original=beginTermsCommand(client,termsReview(opening,after),'synthetic-key');
 finishTermsCommand(client,draft.agreement_id,'another-key','saved');assert.ok(termsCommand(client,draft.agreement_id));
 assert.equal(termsCommand({},draft.agreement_id),null);assert.equal(termsCommand(client,'different'),null);
 finishTermsCommand(client,draft.agreement_id,original.key,'saved');assert.equal(termsCommand(client,draft.agreement_id),null);
});
test('complete material comparisons include fee sponsor, deadlines, confirmation policy and extensions',()=>{
 const changed={...draft,fee_policy:{kind:'sponsor',participant_id:'synthetic-sponsor',amount:'1'},coordination_deadline:'2027-01-01T00:00:00Z',confirmation_policy:{required_confirmations:12},extensions:[{name:'optional',required:false,schema_version:1,value:{synthetic:true}}]};
 assert.deepEqual(termsDifferences(draft,changed).map(item=>item.field),['Fee allocation','Coordination deadline (UTC)','Confirmation policy','Extensions']);
 assert.deepEqual(termsDifferences(draft,{...draft,revision:4}),[]);
});

test('UI review reducer never carries consent through back, stale reset, dismiss or reopen',()=>{
 const review=termsReview(opening,after);let state=freshTermsEditor();
 assert.deepEqual(termsEditorReducer(state,{type:'accept',accepted:true}),{review:null,accepted:false});
 state=termsEditorReducer(state,{type:'review',review});assert.equal(state.accepted,false);
 state=termsEditorReducer(state,{type:'accept',accepted:true});assert.equal(state.accepted,true);
 for(const reason of ['back','stale context','dismiss']){
  const reset=termsEditorReducer(state,{type:'reset'});assert.deepEqual(reset,freshTermsEditor(),reason);
  const reviewed=termsEditorReducer(reset,{type:'review',review});assert.equal(reviewed.accepted,false,reason);
 }
 assert.deepEqual(freshTermsEditor(),{review:null,accepted:false});
});
test('an uncertain retry remains exact through repeated reopen and deterministic retry rejection',()=>{
 const client={};const original=beginTermsCommand(client,termsReview(opening,after),'synthetic-original-key');
 for(let attempt=0;attempt<3;attempt++){
  finishTermsCommand(client,draft.agreement_id,original.key,'uncertain');
  const reopened=freshTermsEditor();assert.equal(reopened.review,null);assert.equal(reopened.accepted,false);
  const request=retryTermsCommand(client,draft.agreement_id);assert.equal(request.encoded,original.encoded);assert.equal(request.revision,original.revision);assert.equal(request.key,original.key);
 }
 finishTermsCommand(client,draft.agreement_id,original.key,'saved');assert.equal(termsCommand(client,draft.agreement_id),null);
});

test('post-commit JSON 500, storage, recovery and unknown errors preserve original request',()=>{
 const client={};const original=beginTermsCommand(client,termsReview(opening,after),'synthetic-original-key');
 for(const error of [{code:'STORAGE_UNAVAILABLE',status:500},{code:'RECOVERY_REQUIRED',status:503},{code:'RECOVERY_REQUIRED',status:409},{code:'UNRECOGNIZED_ERROR',status:400},{code:'INVALID_TERMS',status:500},null]){
  const outcome=termsSaveFailure(error,false);assert.equal(outcome,'uncertain');finishTermsCommand(client,draft.agreement_id,original.key,outcome);
  assert.equal(termsCommand(client,draft.agreement_id).encoded,original.encoded);assert.equal(termsCommand(client,draft.agreement_id).key,original.key);
 }
 assert.equal(termsSaveFailure({code:'REVISION_CONFLICT',status:409},false),'rejected');
 assert.equal(termsSaveFailure({code:'PERMISSION_DENIED',status:403},true),'uncertain');
});
test('late completion cannot refresh a disconnected, replaced or reconnected session',()=>{
 const original={},replacement={};assert.equal(sameTermsSession(original,4,original,4),true);
 for(const [active,generation] of [[null,5],[replacement,5],[original,5]])assert.equal(sameTermsSession(original,4,active,generation),false);
});

test('proposal terms comparison uses complete frozen agreement, independently of proposal counter',()=>{
 const proposal={proposal_id:'synthetic-proposal',agreement_id:draft.agreement_id,revision:31,manifest:{agreement:structuredClone(draft)},manifest_digest:'synthetic-digest'};
 assert.equal(proposalTermsContext(proposal,draft).appliesToCurrentTerms,true);
 assert.equal(proposalTermsContext(proposal,draft).termsRevision,3);
 const history=proposalTermsContext(proposal,after);assert.equal(history.appliesToCurrentTerms,false);assert.equal(history.termsRevision,3);assert.equal(history.currentTermsRevision,4);assert.equal(history.label,'Historical agreement terms');assert.match(history.message,/do not apply to current terms revision 4/);
 for(const changed of [{...draft,purpose:'substituted'},{...draft,recipients:[{...draft.recipients[0],amount:'200000002'}]},{...draft,confirmation_policy:{required_confirmations:11}}])assert.equal(proposalTermsContext(proposal,changed).appliesToCurrentTerms,false);
 assert.equal(proposalTermsContext({...proposal,agreement_id:'different'},draft).appliesToCurrentTerms,false);
 assert.equal(proposalTermsContext({...proposal,manifest:{}},draft).appliesToCurrentTerms,false);
 assert.deepEqual(proposal.manifest.agreement,draft);
});
test('saved integrity reports never transfer from historical, substituted or wrong-bound snapshots',()=>{
 const proposal={proposal_id:'synthetic-proposal',agreement_id:draft.agreement_id,revision:31,manifest:{agreement:structuredClone(draft)},manifest_digest:'synthetic-digest'};
 const report={proposal_id:proposal.proposal_id,manifest_digest:proposal.manifest_digest};
 assert.equal(proposalReportAppliesToCurrentTerms(proposal,report,draft),true);
 assert.equal(proposalReportAppliesToCurrentTerms(proposal,report,after),false);
 assert.equal(proposalReportAppliesToCurrentTerms(proposal,{...report,proposal_id:'another'},draft),false);
 assert.equal(proposalReportAppliesToCurrentTerms(proposal,{...report,manifest_digest:'different'},draft),false);
});
