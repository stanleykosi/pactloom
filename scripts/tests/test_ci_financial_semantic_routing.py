"""Synthetic routing/proof regression fixtures; no native qualification claim."""
import copy
import importlib.util
import json
import pathlib
import sys
import tempfile
import unittest
from unittest.mock import patch
from test_ci_financial_external_output import external_case
ROOT=pathlib.Path(__file__).resolve().parents[1]
def load(name):
 spec=importlib.util.spec_from_file_location('semantic_routing_'+name.replace('-','_'),ROOT/(name+'.py'))
 m=importlib.util.module_from_spec(spec);sys.modules[spec.name]=m;spec.loader.exec_module(m);return m
S=load('ci-financial-supervisor');O=S.P;C=O.C;A=S.A

def semantic_case():
 records,external=external_case()
 links=[next(r for r in records if r['role']==g['role'] and r['sequence']==g['sequence']) for g in external['gates']]
 for r in records:
  r['profile']=C.SEMANTIC_PROFILE
  if r['kind']=='UiSnapshot':r['facts']['host_view_id']=None
 snapshot=next(r for r in records if r['kind']=='UiSnapshot');f=snapshot['facts'];f['host_view_id']=1
 view=dict(rect=[1,1,100,25],nonws=6,rows=1)
 f['host_observation'].update(revision=1,nonws_end=6,view=view)
 f['widgets']=[dict(tag='HostOutput',owner=None,rect=[0,0,120,30],enabled=True)]
 r=copy.deepcopy(snapshot);r['kind']='HostRenderedView';r['facts']=dict(id=1,view_generation=f['view_generation'],revision=1,nonws_end=6,view=copy.deepcopy(view),text='Prompt')
 records.insert(records.index(snapshot),r)
 seq={role:0 for role in C.ROLES}
 for r in records:seq[r['role']]+=1;r['sequence']=seq[r['role']]
 for gate,record in zip(external['gates'],links):gate['sequence']=record['sequence']
 return records,external

class SemanticRoutingTests(unittest.TestCase):
 def test_gate_profile_routes_are_explicit_and_old_remains_callable(self):
  with tempfile.TemporaryDirectory() as tmp:
   root=pathlib.Path(tmp);(root/'ci-financial-contract.py').write_bytes((ROOT/'ci-financial-contract.py').read_bytes())
   with patch.object(S.I,'ROOT',root):
    for mode,profile in [('financial-ui',C.EXTERNAL_PROFILE),('financial-semantic',C.SEMANTIC_PROFILE)]:
     (root/'qualification-gate-mode').write_text(mode+'\n');self.assertEqual(S.I.profile(),profile)
    for mode in ('financial-reuse','unknown','financial-semantic extra'):
     (root/'qualification-gate-mode').write_text(mode+'\n')
     with self.assertRaises(Exception):S.I.profile()
 def test_semantic_recipe_does_not_change_production_or_old_recipe(self):
  old=A.recipe(C.EXTERNAL_PROFILE);new=A.recipe(C.SEMANTIC_PROFILE)
  self.assertEqual(old,A.RECIPE)
  self.assertEqual(new['observed_rustflags'],old['observed_rustflags']+' '+A.SEMANTIC_CFG)
  self.assertEqual(new['qualification_profile'],C.SEMANTIC_PROFILE)
  self.assertEqual(new['production_rustflags'],'');self.assertEqual(new['setup_rustflags'],'')
  self.assertEqual({k:v for k,v in new.items() if k not in ('observed_rustflags','qualification_profile')},
                   {k:v for k,v in old.items() if k!='observed_rustflags'})
  with self.assertRaises(Exception):A.recipe('unreviewed')
 def test_artifact_manifest_cannot_cross_profile(self):
  from test_ci_financial_artifacts import IDENTITY,CLOSURE
  with tempfile.TemporaryDirectory() as tmp:
   root=pathlib.Path(tmp);inputs=root/'inputs';inputs.mkdir()
   for name in A.NAMES:(inputs/name).write_bytes(b'\x7fELFsynthetic-nonexecutable')
   bundle=root/'build.tar';A.export_bundle(inputs,bundle,IDENTITY,CLOSURE,C.SEMANTIC_PROFILE)
   self.assertEqual(A.verify_bundle(bundle,IDENTITY,CLOSURE,C.SEMANTIC_PROFILE)['recipe']['qualification_profile'],C.SEMANTIC_PROFILE)
   with self.assertRaises(Exception):A.verify_bundle(bundle,IDENTITY,CLOSURE)
 def test_runtime_candidate_and_failure_cannot_cross_profile(self):
  for expected,other in ((C.SEMANTIC_PROFILE,C.EXTERNAL_PROFILE),(C.EXTERNAL_PROFILE,C.SEMANTIC_PROFILE)):
   value=dict(schema=1,profile=expected,native_oracle_verified=True,fixture_cleaned=True,display_cleaned=True,public_chain_verified=False,dispatch_attempted=False)
   records=S.RuntimeRecords('external',expected);records(b'CI_FINANCIAL_CANDIDATE '+json.dumps(value).encode());self.assertEqual(records.finish(0)['profile'],expected)
   value['profile']=other
   with self.assertRaises(Exception):S.RuntimeRecords('external',expected)(b'CI_FINANCIAL_CANDIDATE '+json.dumps(value).encode())
   with self.assertRaises(Exception):S.RuntimeRecords('external',expected)(b'CI_FINANCIAL_RESULT '+json.dumps(O.failure('deadline',other)).encode())
 def test_semantic_full_proof_has_distinct_identity_and_same_cleanup_requirement(self):
  records,external=semantic_case();proof=O.validate_completed(records,100,0,external,C.SEMANTIC_PROFILE)
  result=O.public_result(proof,exact_build_verified=True,container_removed=True)
  self.assertEqual(result['profile'],C.SEMANTIC_PROFILE);self.assertFalse(result['synthetic_full_native_verified'])
  self.assertTrue(result['semantic_assisted_host_observation']);self.assertFalse(result['pixel_only_ui_verified'])
  with self.assertRaises(Exception):O.public_result(proof,exact_build_verified=True,container_removed=False)
  with self.assertRaises(Exception):O.validate_completed(records,100,0,external)
  for index in range(14):
   e=copy.deepcopy(external);e['events'].pop(index)
   with self.assertRaises(Exception):O.validate_completed(records,100,0,e,C.SEMANTIC_PROFILE)
 def test_semantic_observation_preserves_genuine_external_protocol_identity(self):
  records,e=semantic_case();self.assertEqual(e['profile'],C.EXTERNAL_PROFILE)
  proof=O.validate_completed(records,100,0,e,C.SEMANTIC_PROFILE)
  self.assertEqual(O.public_result(proof,exact_build_verified=True,container_removed=True)['profile'],C.SEMANTIC_PROFILE)
  for label in (C.SEMANTIC_PROFILE,C.PROFILE,'unknown'):
   changed={**e,'profile':label}
   with self.assertRaises(Exception):O.validate_completed(records,100,0,changed,C.SEMANTIC_PROFILE)
 def test_semantic_shape_alone_cannot_replace_full_proof_or_linkage(self):
  records,e=semantic_case()
  for kind in ('NormalFinished','NormalFinishAdmitted','OwnedReap','SignerMilestone'):
   changed=copy.deepcopy(records);changed.remove(next(r for r in changed if r['kind']==kind))
   with self.assertRaises(Exception):O.validate_completed(changed,100,0,e,C.SEMANTIC_PROFILE)
  for mutate in ('reference','generation','text'):
   changed=copy.deepcopy(records);view=next(r for r in changed if r['kind']=='HostRenderedView')['facts']
   if mutate=='reference':view['id']=2
   elif mutate=='generation':view['view_generation']+=1
   else:view['text']='changed private text'
   with self.assertRaises(Exception):O.validate_completed(changed,100,0,e,C.SEMANTIC_PROFILE)
 def test_old_full_proof_still_valid_and_cannot_be_relabelled(self):
  records,e=external_case();proof=O.validate_completed(records,100,0,e)
  self.assertEqual(O.public_result(proof,exact_build_verified=True,container_removed=True)['profile'],C.EXTERNAL_PROFILE)
  with self.assertRaises(Exception):O.validate_completed(records,100,0,e,C.SEMANTIC_PROFILE)
 def test_semantic_container_does_not_construct_ocr(self):
  from unittest.mock import Mock
  M=load('ci-financial-container')
  session=object.__new__(M.NativeSession);session.deadline=M.time.monotonic_ns()+1_000_000_000
  session.observer=Mock(expected_profile=M.C.SEMANTIC_PROFILE);session.observer.read.return_value=[]
  session.controller=object();session.fixture=object();session.operator=object()
  session.product=Mock(pid=123);session.product.wait.return_value=0
  with patch.object(M.S,'PinnedLocalOcr',side_effect=AssertionError('semantic must not initialize OCR')) as ocr,patch.object(M.FLOW,'FullFlow') as flow:
   self.assertEqual(session.run(),([],123,0));ocr.assert_not_called()
   flow.assert_called_once_with(session.controller,session.fixture,session.observer,None,session.operator)
 def test_fresh_preflight_includes_legacy_fixture_projections_and_real_socket(self):
  shell=(ROOT/'ci-financial-linux.sh').read_text()
  self.assertIn("python3 -I -B -m unittest discover -s scripts/tests -p 'test*financial*.py'",shell)
  self.assertNotIn('test_ci_financial*.py',shell)
  self.assertNotIn('skip',shell)
  self.assertIn('exec python3 -I -B scripts/ci-financial-supervisor.py run',shell)
 def test_workflow_never_labels_semantic_success_pixel_only(self):
  text=(ROOT.parent/'.github/workflows/durable-native-linux.yml').read_text()
  old=text.split('      - name: Distinct financial profile evidence boundary',1)[1].split('      - name:',1)[0]
  new=text.split('      - name: Distinct semantic-assisted financial evidence boundary',1)[1].split('      - name:',1)[0]
  self.assertIn("success() && steps.mode.outputs.gate == 'financial-ui'",old)
  self.assertNotIn('financial-semantic',old)
  self.assertIn("success() && steps.mode.outputs.gate == 'financial-semantic'",new)
  self.assertIn('NOT pixel-only UI qualification',new)
  self.assertIn("always() && (steps.mode.outputs.gate == 'financial-ui' || steps.mode.outputs.gate == 'financial-semantic')",text)
if __name__=='__main__':unittest.main()
