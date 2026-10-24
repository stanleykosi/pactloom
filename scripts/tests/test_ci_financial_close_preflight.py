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
  self.assertEqual(len(C.INTENT_VALIDATION_TESTS),17)
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

class PrimaryCompilerDiagnosticTests(unittest.TestCase):
 def record(self,text,level='error'):
  return json.dumps(dict(reason='compiler-message',message=dict(level=level,rendered=text))).encode()+b'\n'
 def check_bound(self,value):
  self.assertLessEqual(len(value['primary_compiler_errors'].encode())+len(value['combined_stdout_stderr_tail'].encode()),C.S.BUILD_LOG_LIMIT)
 def test_early_primary_errors_survive_large_warning_tail(self):
  raw=self.record('error[E0277]: first\n --> source.rs:42:7')+self.record('error[E0277]: second\n --> source.rs:91:9')+self.record('warning only','warning')+b'warnings\n'*100000
  v=C.preflight_failure_output(raw)
  self.assertEqual(v['primary_error_records'],2)
  self.assertIn('source.rs:42:7',v['primary_compiler_errors']);self.assertIn('source.rs:91:9',v['primary_compiler_errors'])
  self.assertNotIn('warning only',v['primary_compiler_errors']);self.assertEqual(v['captured_output_bytes'],len(raw));self.check_bound(v)
 def test_malformed_or_nonerror_records_do_not_become_primary(self):
  raw=b'{invalid\n[]\n'+json.dumps(dict(reason='compiler-message',message=[])).encode()+b'\n'+self.record('not an error','warning')
  v=C.preflight_failure_output(raw);self.assertEqual(v['primary_error_records'],0);self.assertEqual(v['primary_compiler_errors'],'');self.check_bound(v)
 def test_missing_rendered_preserves_structured_span(self):
  raw=json.dumps(dict(reason='compiler-message',message=dict(level='error',message='bound missing',code=dict(code='E0277'),spans=[dict(file_name='source.rs',line_start=42)]))).encode()
  v=C.preflight_failure_output(raw);self.assertIn('E0277',v['primary_compiler_errors']);self.assertIn('line_start',v['primary_compiler_errors']);self.check_bound(v)
 def test_oversized_unicode_and_secrets_stay_bounded_sanitized(self):
  raw=self.record('ghp_secret123 bearer ABC123 password=private\x1b '+('界'*100000))+b'tail\n'*20000
  v=C.preflight_failure_output(raw);self.check_bound(v)
  self.assertNotIn('ghp_secret123',v['primary_compiler_errors']);self.assertNotIn('ABC123',v['primary_compiler_errors']);self.assertNotIn('password=private',v['primary_compiler_errors']);self.assertNotIn('\x1b',v['primary_compiler_errors'])

class ReportMeasurementTests(unittest.TestCase):
 def value(self,case=False):return {**{k:123 for k in C.REPORT_LENGTHS},**{k:False for k in C.REPORT_VALIDATIONS},'material_input_id':case}
 def line(self,value):return C.REPORT_MEASUREMENT_MARKER+json.dumps(value)
 def output(self,value=None):return self.line(self.value() if value is None else value)+'\n'+self.line(self.value(True))
 def test_exact_closed_measurement_and_libtest_prefix(self):
  v=[self.value(),self.value(True)]
  self.assertEqual(C.report_measurement(self.output()),v)
  self.assertEqual(C.report_measurement('test '+C.REPORT_MEASUREMENT_TEST+' ... '+self.output()+'\nok'),v)
  self.assertEqual(C.report_measurement(self.line(v[1])+'\n'+self.line(v[0])),v)
 def test_schema_types_bounds_and_extra_fields_fail_closed(self):
  cases=[]
  for x in (-1,2*1024*1024+1,True,1.5,float('nan'),float('inf'),'123',None):
   v=self.value();v[C.REPORT_LENGTHS[0]]=x;cases.append(v)
  for x in (0,1,'true',None):
   v=self.value();v[C.REPORT_VALIDATIONS[0]]=x;cases.append(v)
  v=self.value();v['payload']='DO_NOT_PRINT';cases.append(v)
  v=self.value();del v[C.REPORT_LENGTHS[0]];cases.append(v)
  cases += [[],False]
  for v in cases:
   with self.assertRaises(AssertionError):C.report_measurement(self.output(v))
 def test_missing_duplicate_malformed_and_oversized_markers_fail_closed(self):
  one=self.line(self.value());other=self.line(self.value(True));raw=self.output()
  duplicate=C.REPORT_MEASUREMENT_MARKER+'{"pretty_display_bytes":1,"pretty_display_bytes":2}'
  for output in ('',one,raw+'\n'+one,one+'\n'+one,'unknown '+raw,C.REPORT_MEASUREMENT_MARKER+'{invalid\n'+other,duplicate+'\n'+other,C.REPORT_MEASUREMENT_MARKER+' '*2049+json.dumps(self.value())+'\n'+other,raw.replace('_SIZE_V2 ','_SIZE_V1 ')):
   with self.assertRaises(AssertionError):C.report_measurement(output)
 def test_exact_target_only_nocapture_and_normalized_projection(self):
  from unittest import mock
  import contextlib,io
  names=('ordinary_exact_test',C.REPORT_MEASUREMENT_TEST)
  with tempfile.TemporaryDirectory() as td:
   target=pathlib.Path(td);exe=target/'testbin'
   outputs=[b'compiler']+[ (n+': test\n').encode() for n in names]+[b'test result: ok. 1 passed; 0 failed; 0 ignored;',('PRIVATE_SENTINEL\n'+self.output()+'\ntest result: ok. 1 passed; 0 failed; 0 ignored;').encode()]
   captured=io.StringIO()
   with mock.patch.object(C,'INTENT_VALIDATION_TESTS',names),mock.patch.object(C.S,'select_build_environment',return_value={}),mock.patch.object(C,'intent_test_executable',return_value=exe),mock.patch.object(C.S,'checked',side_effect=outputs) as checked,contextlib.redirect_stdout(captured):
    self.assertEqual(C.run_intent_validation_tests(target,{}),2)
   self.assertNotIn('--nocapture',checked.call_args_list[-2].args[0]);self.assertIn('--nocapture',checked.call_args_list[-1].args[0])
   self.assertNotIn('PRIVATE_SENTINEL',captured.getvalue());self.assertIn('CI_RETAINED_REPORT_SIZE_V2 ',captured.getvalue())
 def failure(self,raw,broken=False):
  from unittest import mock
  import contextlib,io
  with tempfile.TemporaryDirectory() as td:
   name=C.REPORT_MEASUREMENT_TEST;error=C.S.Failure('compile','command_failed',raw,exit_status=101);error.cleanup_failed=True;captured=io.StringIO()
   with mock.patch.object(C,'INTENT_VALIDATION_TESTS',(name,)),mock.patch.object(C.S,'select_build_environment',return_value={}),mock.patch.object(C,'intent_test_executable',return_value=pathlib.Path(td)/'testbin'),mock.patch.object(C.S,'checked',side_effect=[b'compiler',(name+': test\n').encode(),error]),contextlib.redirect_stdout(captured):
    with (mock.patch('builtins.print',side_effect=OSError('broken output')) if broken else contextlib.nullcontext()):
     with self.assertRaises(C.S.Failure) as caught:C.run_intent_validation_tests(pathlib.Path(td),{})
   self.assertIs(caught.exception,error);self.assertEqual(error.output,b'');self.assertEqual(error.exit_status,101);self.assertTrue(error.cleanup_failed)
   self.assertNotIn('PRIVATE_SENTINEL',captured.getvalue());self.assertNotIn('PRIVATE_SENTINEL',json.dumps(C.preflight_failure_output(error.output)))
   return captured.getvalue()
 def test_measurement_failure_keeps_original_status_without_output(self):
  self.assertEqual(self.failure(b'PRIVATE_SENTINEL'),'')
  self.assertEqual(self.failure(self.line(self.value()).encode()),'')
 def test_valid_measurement_survives_failed_reproduction_without_raw_output(self):
  output=self.failure(('PRIVATE_SENTINEL\n'+self.output()+'\nfailed static reproduction assertion').encode())
  self.assertEqual(output.splitlines(),['CI_RETAINED_REPORT_SIZE_V2 '+json.dumps([self.value(),self.value(True)],sort_keys=True)])
 def test_failure_projection_print_error_cannot_replace_original(self):
  self.assertEqual(self.failure(self.output().encode(),broken=True),'')
