#!/usr/bin/env python3
"""Exact P53 operation/token restoration after lexical-only Result wrappers.

No genuine authority or Rust execution claimed. Uses existing fixed normalizer;
all added labels are closed constants and original terminal hook is unchanged.
"""
import argparse, hashlib, importlib.util, json, re
from pathlib import Path
BASELINE = "b6c05b04a2f3ecc1ac6695433c3f7a7aa0726ccb"
BASE_TOKEN_HASHES = {'crates/wholepact-signer/src/account/birth/enrollment/roster_v2/prepared_delivery_v3/coordinated_source_entry_v1/coordinated_delivery_source_v1/coordinated_admission_v1.rs': '84ec29dc3e0486ebef8d3003fc56f51585e58587c2b93e7e9fb1ec2a92e434fc', 'crates/wholepact-signer/src/consent_journal/durable_delivery_admission_intent_v3/coordinated_v1.rs': '5af5502e8a85a0360ba350386a01f26cc60fd15baddc313b70904a443c985255', 'crates/wholepact-signer/src/consent_journal/durable_delivery_admission_intent_v3.rs': '8c3b8b341a76fd7ecda292ace6f77f82a73e248c2bf40df9f0c70a3d18019f2a', 'crates/wholepact-signer/src/authority_bridge/mod.rs': '5e016be8b8c4d4174ea44657f14e1ac71c31b77931cd7d9d78b2cf428c71313e'}
ADDED_STAGES = ['AdmitReadIntentAction', 'AdmitReadIntentAuthorityRequest', 'AdmitReadIntentCurrentRows', 'AdmitReadIntentFinancialRows', 'AdmitReadIntentHistoryDigest', 'AdmitReadIntentJournalAccount', 'AdmitReadIntentJournalIdentity', 'AdmitReadIntentJournalSchema', 'AdmitReadIntentOriginalRows', 'AdmitReadIntentReadPresentation', 'AdmitReadIntentReview', 'AdmitReadIntentReviewBinding', 'AdmitReadIntentReviewCeilings', 'AdmitReadIntentReviewDigest', 'AdmitReadIntentReviewMaterial', 'AdmitReadIntentReviewNested', 'AdmitReadIntentReviewShape', 'AdmitReadIntentRowsAccountUse', 'AdmitReadIntentRowsCurrentDisclosure', 'AdmitReadIntentRowsMaterial', 'AdmitReadIntentRowsOriginalDisclosure', 'AdmitReadIntentRowsOriginalLinks', 'AdmitReadIntentRowsSession', 'AdmitReadIntentRowsTransport', 'AdmitReadIntentScope', 'AdmitReadIntentSourceJournal', 'AdmitReadScopeAcquire', 'AdmitReadScopeClaims', 'AdmitReadScopeFixedInputs', 'AdmitReadScopeHistory', 'AdmitReadScopeOriginal', 'AdmitReadScopePermission', 'AdmitReadScopePolicy', 'AdmitReadScopePolicyBinding', 'AdmitReadScopePolicyExport', 'AdmitReadScopePolicyReturns', 'AdmitReadScopeRecipient', 'AdmitReadScopeTerms']
ENUM_BASE_SHA = '74d231041231ac19b46df82276d3e3bbb85a75cde497be5b053dd02cac95d7df'
CALLSITE_HASHES = {'crates/wholepact-signer/src/account/birth/enrollment/roster_v2/prepared_delivery_v3/coordinated_source_entry_v1/coordinated_delivery_source_v1/coordinated_admission_v1.rs': 'b89b1a886f3e32df88b1084054be543b1536772230323ad3522e9d17cf7b9d9b', 'crates/wholepact-signer/src/consent_journal/durable_delivery_admission_intent_v3/coordinated_v1.rs': '98856e38dec54153d0321dcca5478a855b016e0cd605e5c87edf0df56758a523', 'crates/wholepact-signer/src/consent_journal/durable_delivery_admission_intent_v3.rs': 'd5b753a215ab0e82d37d269c3d7982a22407592c739f023c44f5e1e51b3970d5', 'crates/wholepact-signer/src/authority_bridge/mod.rs': '76162c1e42e3ee5fedb89ac8b8407419edbf2402e8b29d57232686bdbee0e0ce'}
CALLSITE_COUNTS = {'AdmitReadIntentAction': 4, 'AdmitReadIntentAuthorityRequest': 1, 'AdmitReadIntentCurrentRows': 1, 'AdmitReadIntentFinancialRows': 1, 'AdmitReadIntentHistoryDigest': 1, 'AdmitReadIntentJournalAccount': 1, 'AdmitReadIntentJournalIdentity': 2, 'AdmitReadIntentJournalSchema': 1, 'AdmitReadIntentOriginalRows': 1, 'AdmitReadIntentReadPresentation': 1, 'AdmitReadIntentReview': 2, 'AdmitReadIntentReviewBinding': 1, 'AdmitReadIntentReviewCeilings': 2, 'AdmitReadIntentReviewDigest': 1, 'AdmitReadIntentReviewMaterial': 3, 'AdmitReadIntentReviewNested': 7, 'AdmitReadIntentReviewShape': 3, 'AdmitReadIntentRowsAccountUse': 4, 'AdmitReadIntentRowsCurrentDisclosure': 3, 'AdmitReadIntentRowsMaterial': 4, 'AdmitReadIntentRowsOriginalDisclosure': 2, 'AdmitReadIntentRowsOriginalLinks': 15, 'AdmitReadIntentRowsSession': 2, 'AdmitReadIntentRowsTransport': 2, 'AdmitReadIntentScope': 1, 'AdmitReadIntentSourceJournal': 2, 'AdmitReadScopeAcquire': 2, 'AdmitReadScopeClaims': 1, 'AdmitReadScopeFixedInputs': 1, 'AdmitReadScopeHistory': 2, 'AdmitReadScopeOriginal': 6, 'AdmitReadScopePermission': 5, 'AdmitReadScopePolicy': 1, 'AdmitReadScopePolicyBinding': 1, 'AdmitReadScopePolicyExport': 4, 'AdmitReadScopePolicyReturns': 4, 'AdmitReadScopeRecipient': 2, 'AdmitReadScopeTerms': 2, 'AdmitReadSourceAcquire': 1, 'AdmitReadSourceAction': 4, 'AdmitReadSourceBinding': 1, 'AdmitReadSourceCurrent': 2, 'AdmitReadSourceLeasePermission': 1, 'AdmitReadSourcePresentation': 1, 'AdmitReadSourcePurpose': 1, 'AdmitReadSourceRecords': 1, 'AdmitReadSourceRetained': 1, 'AdmitReadSourceRevision': 2, 'AdmitReadSourceRevisionMissing': 1}
TEST_FOOTER = '\n#[cfg(all(test, feature = "synthetic-qualification"))]\n#[path = "coordinated_v1/full_intent_validation_tests.rs"]\nmod full_intent_validation_tests;\n'
TEST_PEEK = '\n// Test-only finite observation; cannot set metadata or mint native authority.\n#[cfg(test)]\npub(crate) fn admit_read_detail_for_test() -> Option<(DriverStage, Class)> {\n    ADMIT_READ_DETAIL.with(|slot| slot.get().flatten())\n}\n'
UNCHANGED = {'crates/wholepact-signer/src/lib.rs': '83e2424be07c90d42cb41db56ac93e94b81b322ab68e39329516174d2e512f5f', 'crates/wholepact-signer/src/financial_ci_actor.rs': 'e7655f95e8e4d7845ee4499475a6823074c6b394d89ce327ba60520871964a1a', 'crates/wholepact-signer/src/native_ui/runtime/coordinated_delivery_admission_v1.rs': '59c9fc8331a83323fab2d85ae4f0de853888af1eadcf090561d01b574846ef46', 'crates/wholepact-financial-coordinator-origin/src/signer_v3_admit_read_origin.rs': 'ed874cb1966596cea5ef563fea08853ec669a57948972fc370c6c7c068e8a6d3', 'crates/wholepact-financial-coordinator-origin/src/signer_continue_state.rs': 'f22c0ad3452dc038b0e34f45f8fbd1182c11113d6977d15b1bb347e838fe6cea'}
# Lossless full nine-item review JSON compacted only for the existing wire
# budget; restore this exact method prefix for the historical operation audit.
COMPACT_DISPLAY = '    pub(crate) fn display(&self) -> Result<String> {\n        serde_json::to_string(&('
PRETTY_DISPLAY = '    pub(crate) fn display(&self) -> Result<String> {\n        serde_json::to_string_pretty(&('

# Exactly the two pre-existing implicit `?` conversions made explicit before
# finite classification; not a general permission/error remapping allowance.
IDENTITY_CONVERSIONS = [
 'self.database_identity.check_current(&c).map_err(JournalError::from)',
 'self.database_identity.check_current(&tx).map_err(JournalError::from)',
]

# Exact cfg(test)-only pure projection alias; no production policy change.
TEST_PROJECTION_EXPORT = '\n// Test-only access to pure data projections; no authority constructors.\n#[cfg(all(test, feature = "coordinated-financial-workflow-v1", feature = "durable-proposal", feature = "pending-birth-owner-signing", feature = "native-ui", target_os = "linux"))]\npub(crate) use financial_continuation_v1::project_return_display;\n'

def main():
 p=argparse.ArgumentParser();p.add_argument('--source',type=Path,required=True);root=p.parse_args().source.resolve()
 spec=importlib.util.spec_from_file_location('prior',root/'scripts/ci-financial-admit-read-source-audit.py')
 prior=importlib.util.module_from_spec(spec);spec.loader.exec_module(prior)
 evidence=[];counts={}
 for relative,expected in BASE_TOKEN_HASHES.items():
  raw=(root/relative).read_text();restored=raw.replace(TEST_FOOTER,'')
  if relative == 'crates/wholepact-signer/src/authority_bridge/mod.rs':
   assert restored.count(TEST_PROJECTION_EXPORT)==1
   restored=restored.replace(TEST_PROJECTION_EXPORT,'',1)
  if relative.endswith('/coordinated_v1.rs'):
   assert restored.count(COMPACT_DISPLAY)==1
   restored=restored.replace(COMPACT_DISPLAY,PRETTY_DISPLAY)
   for conversion in IDENTITY_CONVERSIONS:
    assert restored.count(conversion)==1
    restored=restored.replace(conversion,conversion.removesuffix('.map_err(JournalError::from)'))
  assert prior.digest(prior.tokens(prior.unwrap(restored)))==expected,relative
  calls=[]
  for match in re.finditer(r'actor_admit_read_detail_result!\((\w+),',raw):
   end=prior.balanced_end(raw,raw.index('(',match.start()))
   calls.append(prior.tokens(raw[match.start():end])); label=match.group(1)
   counts[label]=counts.get(label,0)+1
  assert hashlib.sha256(json.dumps(calls,separators=(',',':')).encode()).hexdigest()==CALLSITE_HASHES[relative],relative
  evidence.append({'path':relative,'source_sha256':prior.digest(raw),'baseline_tokens':expected})
 assert counts==CALLSITE_COUNTS
 for relative,expected in UNCHANGED.items():
  raw=(root/relative).read_text()
  if relative.endswith('/runtime/coordinated_delivery_admission_v1.rs'):
   raw=prior.restore_ready_worker(raw)
  if relative.endswith('/financial_ci_actor.rs'):
   assert raw.count(TEST_PEEK)==1
   raw=raw.replace(TEST_PEEK,'')
  assert hashlib.sha256(raw.encode()).hexdigest()==expected,relative
 enum=(root/'crates/wholepact-financial-coordinator-origin/src/financial_ci_actor_diagnostics.rs').read_text()
 for label in ADDED_STAGES:assert re.search(r'\b'+label+r'\b',enum),label
 restored_enum=enum.replace(','+','.join(ADDED_STAGES),'')
 assert hashlib.sha256(restored_enum.encode()).hexdigest()==ENUM_BASE_SHA
 # No new metadata carrier, observer, terminal hook, wire field, or cfg consumer.
 print(json.dumps({'baseline':BASELINE,'source_audit_passed':True,'runtime_execution':False,
  'normalized':evidence,'added_stages':ADDED_STAGES,'unchanged_close_and_capture':UNCHANGED},sort_keys=True))
if __name__=='__main__':main()
