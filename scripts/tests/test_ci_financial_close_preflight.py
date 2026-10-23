"""Pure fixed context-check regression; no compiler, network, native process or socket."""
import copy,importlib.util,json,pathlib,tempfile,unittest
P=pathlib.Path(__file__).resolve().parents[1]/'ci-close-preflight-contexts.py'
spec=importlib.util.spec_from_file_location('close_context_preflight',P);C=importlib.util.module_from_spec(spec);spec.loader.exec_module(C)
class ContextPreflightTests(unittest.TestCase):
 def setUp(self):
  self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup);self.target=pathlib.Path(self.tmp.name);self.rows=[]
  for crate in C.SCRIPTS:
   package='path+file:///reviewed/'+crate+'#'+crate+'@0.1.0';out=self.target/crate;out.mkdir()
   self.rows += [dict(reason='compiler-artifact',package_id=package,manifest_path=str(C.S.REPO/'crates'/crate/'Cargo.toml'),target=dict(kind=['custom-build'],name='build-script-build',src_path=str(C.S.REPO/'crates'/crate/'build.rs'))),dict(reason='build-script-executed',package_id=package,cfgs=list(C.S.A.FINANCIAL_CFGS),linked_libs=[],linked_paths=[],env=[],out_dir=str(out))]
  for crate in C.PACKAGES:self.rows.append(dict(reason='compiler-artifact',manifest_path=str(C.S.REPO/'crates'/crate/'Cargo.toml'),profile=dict(test=True),features=C.S.A.RECIPE['artifact_features']['coordinator-observed'] if crate=='wholepact-financial-coordinator' else [],target=dict(kind=['bin'] if crate=='wholepact-financial-coordinator' else ['lib'],name=crate if crate=='wholepact-financial-coordinator' else crate.replace('-','_'),src_path=str(C.S.REPO/'crates'/crate/'src'/('main.rs' if crate=='wholepact-financial-coordinator' else 'lib.rs')))))
 def check(self,rows):C.validate(b'\n'.join(json.dumps(x).encode() for x in rows),self.target)
 def test_exact_scopes_and_all_test_contexts(self):
  self.check(self.rows);self.assertEqual(set(C.SCRIPTS),{'wholepact-financial-coordinator','wholepact-native-host','wholepact-financial-coordinator-origin','wholepact-signer'});self.assertIn('wholepact-authority',C.PACKAGES);self.assertIn('wholepact-financial-coordinator',C.PACKAGES)
 def test_missing_duplicate_or_wrong_cfg_reject(self):
  for rows in (self.rows[1:],self.rows[:-1],self.rows+[self.rows[0]],self.rows+[self.rows[1]]):
   with self.assertRaises(AssertionError):self.check(rows)
  for cfgs in ([],['wholepact_financial_ci'],list(reversed(C.S.A.FINANCIAL_CFGS))):
   rows=copy.deepcopy(self.rows);rows[1]['cfgs']=cfgs
   with self.assertRaises(AssertionError):self.check(rows)
 def test_foreign_consumer_and_script_path_reject(self):
  for field,value in [('manifest_path',str(C.S.REPO/'crates/unknown/Cargo.toml'))]:
   rows=copy.deepcopy(self.rows);rows[0][field]=value
   with self.assertRaises(AssertionError):self.check(rows)
  rows=copy.deepcopy(self.rows);rows[0]['target']['src_path']='/wrong/build.rs'
  with self.assertRaises(AssertionError):self.check(rows)
  rows=copy.deepcopy(self.rows);rows[1]['package_id']='foreign'
  with self.assertRaises(AssertionError):self.check(rows)
 def test_non_library_or_non_boolean_test_context_rejected(self):
  for key,value in [('kind',['bin']),('kind',['test']),('name','wrong'),('src_path','/wrong/lib.rs')]:
   rows=copy.deepcopy(self.rows);rows[-1]['target'][key]=value
   with self.assertRaises(AssertionError):self.check(rows)
  for value in (1,'true',False):
   rows=copy.deepcopy(self.rows);rows[-1]['profile']['test']=value
   with self.assertRaises(AssertionError):self.check(rows)
 def test_coordinator_requires_exact_binary_test_context(self):
  index=next(i for i,r in enumerate(self.rows) if r.get('profile',{}).get('test') and r['manifest_path']==str(C.S.REPO/'crates/wholepact-financial-coordinator/Cargo.toml'))
  for key,value in [('kind',['lib']),('name','wholepact_financial_coordinator'),('name','other'),('src_path','/wrong/main.rs')]:
   rows=copy.deepcopy(self.rows);rows[index]['target'][key]=value
   with self.assertRaises(AssertionError):self.check(rows)
  for features in ([],['common-image-bootstrap'],C.S.A.RECIPE['artifact_features']['coordinator-observed']+['extra']):
   rows=copy.deepcopy(self.rows);rows[index]['features']=features
   with self.assertRaises(AssertionError):self.check(rows)
  rows=copy.deepcopy(self.rows);rows[index]['profile']['test']=False
  with self.assertRaises(AssertionError):self.check(rows)
 def test_side_effects_and_output_escape_reject(self):
  for key,value in [('linked_libs',['x']),('linked_paths',['/x']),('env',[['KEY','x']]),('out_dir','/')]:
   rows=copy.deepcopy(self.rows);rows[1][key]=value
   with self.assertRaises(AssertionError):self.check(rows)
 def test_fixed_preflight_never_executes_runtime_or_changes_recipe(self):
  text=P.read_text();self.assertIn("'cargo','check'",text);self.assertNotIn('build_inputs(',text);self.assertNotIn('export_compiled_artifacts(',text);self.assertNotIn('docker',text);self.assertEqual(C.S.A.RECIPE['build_recipe_version'],3)
