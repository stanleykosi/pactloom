import {test} from 'node:test';
import assert from 'node:assert/strict';
import {describeAgreementScope} from '../dist/index.js';
test('selected scope names exact IDs and never promises future ownership',()=>{
 const text=describeAgreementScope({all_agreements:false,include_owned_agreements:false,agreement_ids:['chosen']});
 assert.match(text,/Only these exact selected/);assert.match(text,/chosen/);assert.match(text,/do not expand/);
});
test('legacy omitted ownership remains unknown and explicit broad grants remain visible',()=>{
 assert.match(describeAgreementScope({all_agreements:false,agreement_ids:[]}),/did not report/);
 assert.match(describeAgreementScope({all_agreements:false,include_owned_agreements:true,agreement_ids:[]}),/All existing and future owned/);
 assert.match(describeAgreementScope({all_agreements:true,agreement_ids:[]}),/All local agreements/);
});

test('contradictory scope report does not claim selected access',()=>{
 assert.match(describeAgreementScope({all_agreements:true,include_owned_agreements:false,agreement_scope:'selected',agreement_ids:['a']}),/Inconsistent/);
});
