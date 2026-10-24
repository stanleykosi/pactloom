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

class SignerAbsencePreflightTests(unittest.TestCase):
 def setUp(self):
  self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup);self.target=pathlib.Path(self.tmp.name);self.rows=[]
  for crate in C.SIGNER_SCRIPTS:
   package='path+file:///reviewed/'+crate+'#'+crate+'@0.1.0';out=self.target/crate;out.mkdir()
   self.rows += [dict(reason='compiler-artifact',package_id=package,manifest_path=str(C.S.REPO/'crates'/crate/'Cargo.toml'),target=dict(kind=['custom-build'],name='build-script-build',src_path=str(C.S.REPO/'crates'/crate/'build.rs'))),dict(reason='build-script-executed',package_id=package,cfgs=[],linked_libs=[],linked_paths=[],env=[],out_dir=str(out))]
  self.metadata=self.target/'libwholepact_signer-exact.rmeta';self.metadata.write_bytes(b'nonexecuted fixture')
  self.rows.append(dict(reason='compiler-artifact',manifest_path=str(C.S.REPO/'crates/wholepact-signer/Cargo.toml'),profile=dict(test=False),features=list(C.SIGNER_FEATURES),filenames=[str(self.metadata)],target=dict(kind=['lib'],name='wholepact_signer',src_path=str(C.S.REPO/'crates/wholepact-signer/src/lib.rs'))))
 def check(self,rows,cfgs=()):return C.signer_metadata(b'\n'.join(json.dumps(x).encode() for x in rows),self.target,cfgs)
 def test_exact_non_test_metadata_and_two_script_scopes(self):
  self.assertEqual(self.check(self.rows),self.metadata)
  pixel=copy.deepcopy(self.rows)
  for row in pixel:
   if row['reason']=='build-script-executed':row['cfgs']=list(C.S.A.FINANCIAL_CFGS[:2])
  self.assertEqual(self.check(pixel,C.S.A.FINANCIAL_CFGS[:2]),self.metadata)
  with self.assertRaises(AssertionError):self.check(pixel)
 def test_wrong_target_features_profile_or_metadata_rejected(self):
  for field,value in [('features',[]),('features',list(C.SIGNER_FEATURES)+['extra']),('profile',dict(test=True)),('profile',dict(test=0)),('filenames',[]),('filenames',['/outside.rmeta'])]:
   rows=copy.deepcopy(self.rows);rows[-1][field]=value
   with self.assertRaises(AssertionError):self.check(rows)
  for field,value in [('kind',['bin']),('name','other'),('src_path','/wrong.rs')]:
   rows=copy.deepcopy(self.rows);rows[-1]['target'][field]=value
   with self.assertRaises(AssertionError):self.check(rows)
  with self.assertRaises(AssertionError):self.check(self.rows+[self.rows[-1]])
 def test_absence_must_be_specific_method_e0599(self):
  for _,method in C.SIGNER_PROBES:
   row=dict(level='error',code=dict(code='E0599'),message='no function named '+method)
   raw=json.dumps(row).encode();C.absent_method_diagnostic(1,raw,method)
   for status,data in [(0,raw),(1,b''),(1,json.dumps(row|dict(code=dict(code='E0463'))).encode()),(1,json.dumps(row|dict(message='another method')).encode()),(1,raw+b'\n'+raw)]:
    with self.assertRaises(AssertionError):C.absent_method_diagnostic(status,data,method)
 def test_no_extra_cfg_consumer_or_side_effects(self):
  for field,value in [('cfgs',list(C.S.A.FINANCIAL_CFGS)),('linked_libs',['x']),('env',[['X','y']]),('out_dir','/')]:
   rows=copy.deepcopy(self.rows);rows[1][field]=value
   with self.assertRaises(AssertionError):self.check(rows)
  for rows in (self.rows[2:],self.rows+[self.rows[0]],self.rows+[dict(reason='build-script-executed',package_id='unexpected',cfgs=['wholepact_financial_ci'])]):
   with self.assertRaises(AssertionError):self.check(rows)
 def test_expected_signer_features_equal_actual_local_feature_closure(self):
  import tomllib
  features=tomllib.loads((C.S.REPO/'crates/wholepact-signer/Cargo.toml').read_text())['features'];seen=set()
  def visit(name):
   if name in seen:return
   seen.add(name)
   for child in features[name]:
    if '/' not in child and not child.startswith('dep:'):visit(child)
  visit('coordinated-financial-workflow-v1');self.assertEqual(sorted(seen),list(C.SIGNER_FEATURES))

class HandoffSecurityExecutionPreflightTests(unittest.TestCase):
 def setUp(self):
  SignerAbsencePreflightTests.setUp(self)
  for row in self.rows:
   if row['reason']=='build-script-executed':row['cfgs']=list(C.S.A.FINANCIAL_CFGS)
  self.rows[-1]['profile']={'test':True};self.rows[-1]['executable']=str(self.metadata)
 def check(self,rows,cfgs=()):return C.signer_test_executable(b'\n'.join(json.dumps(x).encode() for x in rows),self.target)
 def test_exact_test_executable_and_two_script_scopes(self):
  self.assertEqual(self.check(self.rows),self.metadata)
 def test_wrong_target_features_profile_or_metadata_rejected(self):
  for field,value in [('features',[]),('profile',dict(test=False)),('profile',dict(test=1)),('executable','/outside'),('filenames',[])]:
   rows=copy.deepcopy(self.rows);rows[-1][field]=value
   with self.assertRaises(AssertionError):self.check(rows)
  for field,value in [('kind',['bin']),('kind',['test']),('name','other'),('src_path','/wrong.rs')]:
   rows=copy.deepcopy(self.rows);rows[-1]['target'][field]=value
   with self.assertRaises(AssertionError):self.check(rows)
  with self.assertRaises(AssertionError):self.check(self.rows+[self.rows[-1]])
 def test_no_extra_cfg_consumer_or_side_effects(self):
  for field,value in [('cfgs',[]),('linked_libs',['x']),('env',[['X','y']]),('out_dir','/')]:
   rows=copy.deepcopy(self.rows);rows[1][field]=value
   with self.assertRaises(AssertionError):self.check(rows)
 def test_fixed_execution_rejects_empty_listing_ignored_or_zero_pass(self):
  from unittest import mock
  import contextlib,io
  name='consent_journal::authority::coordinated_preconstruction_v1::handoff_security_tests::fixed_fixture'
  for listing,result,ok in [(name+': test\n','test result: ok. 1 passed; 0 failed; 0 ignored;',True),('', 'test result: ok. 1 passed; 0 failed; 0 ignored;',False),(name+': test\n','test result: ok. 0 passed; 0 failed; 1 ignored;',False)]:
   with mock.patch.object(C,'HANDOFF_SECURITY_TESTS',(name,)),mock.patch.object(C.S,'select_build_environment',return_value={}),mock.patch.object(C,'signer_test_executable',return_value=self.metadata),mock.patch.object(C.S,'checked',side_effect=[b'compiler',listing.encode(),result.encode()]) as checked,contextlib.redirect_stdout(io.StringIO()):
    if ok:self.assertEqual(C.run_handoff_security_tests(self.target,{}),1)
    else:
     with self.assertRaises(AssertionError):C.run_handoff_security_tests(self.target,{})
    self.assertEqual(checked.call_args_list[0].kwargs['seconds'],900)
    for call in checked.call_args_list[1:]:self.assertLessEqual(call.kwargs['seconds'],30)

class FixtureLifetimeExecutionPreflightTests(unittest.TestCase):
 def setUp(self):
  self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup);self.target=pathlib.Path(self.tmp.name);self.rows=[];self.executables={}
  for crate in ('wholepact-native-host','wholepact-signer'):
   package='path+file:///reviewed/'+crate+'#'+crate+'@0.1.0';out=self.target/crate;out.mkdir()
   self.rows.extend([dict(reason='compiler-artifact',package_id=package,manifest_path=str(C.S.REPO/'crates'/crate/'Cargo.toml'),target=dict(kind=['custom-build'],name='build-script-build',src_path=str(C.S.REPO/'crates'/crate/'build.rs'))),dict(reason='build-script-executed',package_id=package,cfgs=[],linked_libs=[],linked_paths=[],env=[],out_dir=str(out))])
  for kind,(crate,features,_,_) in C.FIXTURE_TARGETS.items():
   exe=self.target/(crate+'-test');exe.write_bytes(b'not executed');self.executables[kind]=exe
   self.rows.append(dict(reason='compiler-artifact',manifest_path=str(C.S.REPO/'crates'/crate/'Cargo.toml'),profile=dict(test=True),features=list(features),executable=str(exe),filenames=[str(exe)],target=dict(kind=['lib'],name=crate.replace('-','_'),src_path=str(C.S.REPO/'crates'/crate/'src/lib.rs'))))
 def check(self,rows,kind):return C.fixture_test_executable(b'\n'.join(json.dumps(x).encode() for x in rows),self.target,kind)
 def test_exact_pristine_two_targets_and_empty_cfg(self):
  for kind in C.FIXTURE_TARGETS:self.assertEqual(self.check(self.rows,kind),self.executables[kind])
 def test_wrong_test_identity_features_or_executable_rejected(self):
  for index,kind in [(4,'authority'),(5,'pristine-host')]:
   for field,value in [('profile',dict(test=1)),('features',[]),('executable','/outside'),('filenames',[])]:
    rows=copy.deepcopy(self.rows);rows[index][field]=value
    with self.assertRaises(AssertionError):self.check(rows,kind)
   for field,value in [('kind',['bin']),('name','incorrect'),('src_path','/outside.rs')]:
    rows=copy.deepcopy(self.rows);rows[index]['target'][field]=value
    with self.assertRaises(AssertionError):self.check(rows,kind)
   with self.assertRaises(AssertionError):self.check(self.rows+[self.rows[index]],kind)
 def test_semantic_cfg_extra_consumer_and_script_side_effect_rejected(self):
  for field,value in [('cfgs',['wholepact_financial_ci']),('env',[['X','Y']]),('linked_libs',['x']),('out_dir','/')]:
   rows=copy.deepcopy(self.rows);rows[1][field]=value
   with self.assertRaises(AssertionError):self.check(rows,'authority')
  rows=copy.deepcopy(self.rows);rows[0]['manifest_path']=str(C.S.REPO/'crates/wholepact-financial-coordinator-origin/Cargo.toml')
  with self.assertRaises(AssertionError):self.check(rows,'pristine-host')
 def test_all_selected_names_listed_before_any_execution_and_failure_closed(self):
  from unittest import mock
  import contextlib,io
  selected={kind:(crate,features,scripts,(kind+'::fixed',)) for kind,(crate,features,scripts,_) in C.FIXTURE_TARGETS.items()}
  for bad in (None,'listing','ignored'):
   outputs=[b'compiler',b'authority::fixed: test\n',b'pristine-host::fixed: test\n',b'test result: ok. 1 passed; 0 failed; 0 ignored;',b'test result: ok. 1 passed; 0 failed; 0 ignored;']
   if bad=='listing':outputs[2]=b''
   if bad=='ignored':outputs[3]=b'test result: ok. 0 passed; 0 failed; 1 ignored;'
   with mock.patch.object(C,'FIXTURE_TARGETS',selected),mock.patch.object(C.S,'select_build_environment',return_value={}),mock.patch.object(C,'fixture_test_executable',side_effect=lambda raw,target,kind:self.executables[kind]),mock.patch.object(C.S,'checked',side_effect=outputs) as checked,contextlib.redirect_stdout(io.StringIO()):
    if bad:
     with self.assertRaises(AssertionError):C.run_fixture_lifetime_tests(self.target,{})
    else:self.assertEqual(C.run_fixture_lifetime_tests(self.target,{}),2)
    self.assertEqual(checked.call_args_list[0].kwargs['seconds'],900)
    if bad=='listing':self.assertEqual(checked.call_count,3)
    for call in checked.call_args_list[1:]:self.assertLessEqual(call.kwargs['seconds'],30)

class IntentValidationExecutionPreflightTests(unittest.TestCase):
 def setUp(self):
  SignerAbsencePreflightTests.setUp(self)
  for row in self.rows:
   if row['reason']=='build-script-executed':row['cfgs']=list(C.S.A.FINANCIAL_CFGS)
  self.rows[-1]['features']=list(C.INTENT_FEATURES);self.rows[-1]['profile']={'test':True};self.rows[-1]['executable']=str(self.metadata)
 def check(self,rows,cfgs=()):return C.intent_test_executable(b'\n'.join(json.dumps(x).encode() for x in rows),self.target)
 def test_exact_test_executable_and_two_script_scopes(self):
  self.assertEqual(self.check(self.rows),self.metadata)
 def test_wrong_target_features_profile_or_metadata_rejected(self):
  for field,value in [('features',[]),('profile',dict(test=False)),('profile',dict(test=1)),('executable','/outside'),('filenames',[])]:
   rows=copy.deepcopy(self.rows);rows[-1][field]=value
   with self.assertRaises(AssertionError):self.check(rows)
  for field,value in [('kind',['bin']),('kind',['test']),('name','other'),('src_path','/wrong.rs')]:
   rows=copy.deepcopy(self.rows);rows[-1]['target'][field]=value
   with self.assertRaises(AssertionError):self.check(rows)
  with self.assertRaises(AssertionError):self.check(self.rows+[self.rows[-1]])
 def test_no_extra_cfg_consumer_or_side_effects(self):
  for field,value in [('cfgs',[]),('linked_libs',['x']),('env',[['X','y']]),('out_dir','/')]:
   rows=copy.deepcopy(self.rows);rows[1][field]=value
   with self.assertRaises(AssertionError):self.check(rows)
 def test_fixed_execution_rejects_empty_listing_ignored_or_zero_pass(self):
  from unittest import mock
  import contextlib,io
  name='consent_journal::authority::coordinated_preconstruction_v1::handoff_security_tests::fixed_fixture'
  for listing,result,ok in [(name+': test\n','test result: ok. 1 passed; 0 failed; 0 ignored;',True),('', 'test result: ok. 1 passed; 0 failed; 0 ignored;',False),(name+': test\n','test result: ok. 0 passed; 0 failed; 1 ignored;',False)]:
   with mock.patch.object(C,'INTENT_VALIDATION_TESTS',(name,)),mock.patch.object(C.S,'select_build_environment',return_value={}),mock.patch.object(C,'intent_test_executable',return_value=self.metadata),mock.patch.object(C.S,'checked',side_effect=[b'compiler',listing.encode(),result.encode()]) as checked,contextlib.redirect_stdout(io.StringIO()):
    if ok:self.assertEqual(C.run_intent_validation_tests(self.target,{}),1)
    else:
     with self.assertRaises(AssertionError):C.run_intent_validation_tests(self.target,{})
    self.assertEqual(checked.call_args_list[0].kwargs['seconds'],900)
    for call in checked.call_args_list[1:]:self.assertLessEqual(call.kwargs['seconds'],60)

 def test_intent_feature_union_is_exact_and_does_not_replace_old_target(self):
  self.assertEqual(set(C.INTENT_FEATURES),set(C.SIGNER_FEATURES)|{'synthetic-qualification'})
  self.assertEqual(len(C.HANDOFF_SECURITY_TESTS),50)
  self.assertEqual(len(C.INTENT_VALIDATION_TESTS),13)
  self.assertTrue(set(C.INTENT_VALIDATION_TESTS).isdisjoint(C.HANDOFF_SECURITY_TESTS))
  rows=copy.deepcopy(self.rows);rows[-1]['features']=list(C.SIGNER_FEATURES)
  with self.assertRaises(AssertionError):self.check(rows)
  with self.assertRaises(AssertionError):C.signer_test_executable(b'\n'.join(json.dumps(x).encode() for x in self.rows),self.target)

class IntentTimingEvidenceTests(unittest.TestCase):
 def test_harness_interval_is_bounded_integer_not_runtime_time(self):
  from unittest import mock
  for now,expected in [(100,0),(101.5,1500),(460,360000)]:
   with mock.patch.object(C.time,'monotonic',return_value=now):
    self.assertEqual(C.intent_elapsed_ms(100),expected)
    self.assertIs(type(C.intent_elapsed_ms(100)),int)
  for now in (99,460.001,float('nan'),float('inf')):
   with mock.patch.object(C.time,'monotonic',return_value=now):
    with self.assertRaises(AssertionError):C.intent_elapsed_ms(100)
