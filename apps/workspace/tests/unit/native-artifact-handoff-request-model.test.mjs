import {test} from 'node:test';
import assert from 'node:assert/strict';
import {nativeArtifactHandoffRequestMetadata,canRequestArtifactHandoff} from '../../src/native-artifact-handoff-request-model.ts';
const job='proof-'+'a'.repeat(64);
const item=()=>({schema_version:1,operation:'artifact_handoff',kind:'signer_review',proved_artifact_digest:'9'.repeat(64),request_id:'b'.repeat(64),agreement_id:'agreement',candidate_id:'candidate',manifest_digest:'c'.repeat(64),original_revision:7,queued_revision:8,attempt_revision:null,state:'queued',authorization_allowed:false,result_status:'unknown_not_financial_evidence',job_id:job,receipt_storage_key:'d'.repeat(64),receipt_digest:'e'.repeat(64),scope_digest:'f'.repeat(64),coordination_request_digest:'1'.repeat(64),handoff_status:'not_attempted'});
test('handoff metadata cannot claim signature approval or omit exact artifact',()=>{
 assert.equal(nativeArtifactHandoffRequestMetadata([item()],'agreement').length,1);
 for(const patch of [{kind:'sign'},{proved_artifact_digest:undefined},{authorization_allowed:true},{handoff_status:'completed'}])assert.throws(()=>nativeArtifactHandoffRequestMetadata([{...item(),...patch}],'agreement'));
});
test('uncertain handoffs block same kind replacement and preserve distinct intake purpose',()=>{
 const unknown={...item(),state:'attempt_started',attempt_revision:9,handoff_status:'attempted_outcome_unknown'};
 assert.equal(canRequestArtifactHandoff([unknown],'candidate',job,'signer_review',true,false,false),false);
 assert.equal(canRequestArtifactHandoff([unknown],'candidate',job,'signature_intake',true,false,false),true);
 assert.equal(canRequestArtifactHandoff([],'candidate',job,'signature_intake',true,false,true),false);
});
