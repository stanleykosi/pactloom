"""Pure fixed context-check regression; no compiler, network, native process or socket."""
import copy,importlib.util,json,pathlib,tempfile,unittest
P=pathlib.Path(__file__).resolve().parents[1]/'ci-close-preflight-contexts.py'
spec=importlib.util.spec_from_file_location('close_context_preflight',P);C=importlib.util.module_from_spec(spec);spec.loader.exec_module(C)
class ExactHistorySourceRestorationTests(unittest.TestCase):
 def test_only_exact_diagnostic_and_test_additions_restore_historical_bytes(self):
  import hashlib
  path=P.parent/'ci-financial-admit-read-source-audit.py'
  spec=importlib.util.spec_from_file_location('fixed_p70_source_restoration',path);audit=importlib.util.module_from_spec(spec);spec.loader.exec_module(audit)
  base=P.parent.parent/'crates'
  cases=[
   (base/'wholepact-signer/src/native_ui/runtime/coordinated_delivery_admission_v1.rs',audit.restore_ready_worker,'59c9fc8331a83323fab2d85ae4f0de853888af1eadcf090561d01b574846ef46','Ok(None)','Ok(Some(v))'),
   (base/'wholepact-financial-coordinator-origin/src/financial_observer.rs',audit.restore_history_observer,'67a92e04a03df01257be85ee99c8544be4f627c05c3800a6b5ae9b82cbd6dc4a','WRITER.try_lock()','WRITER.lock()'),
   (base/'wholepact-financial-coordinator-origin/src/financial_ci_actor_diagnostics.rs',audit.restore_history_actor,'84ebadcad2265ff1945995ffbb0e0c8c90ae5bcb7658bf3524b4c6a3700a80e4','HistoryMonitorCheck','HistoryUnknown'),
   (base/'wholepact-financial-coordinator-origin/src/signer_continue_state.rs',audit.restore_shared_wall_regression,'f22c0ad3452dc038b0e34f45f8fbd1182c11113d6977d15b1bb347e838fe6cea','wall < prior','wall <= prior'),
   (base/'wholepact-financial-coordinator/src/financial_source_ui.rs',audit.restore_ui_repaint,'e7eab264c493c758e8723576fb476b1373204502d35d125113ede6d537dbdc96','from_millis(20)','from_millis(21)'),
  ]
  for source,restore,expected,old,new in cases:
   raw=source.read_text()
   def verify(text):self.assertEqual(hashlib.sha256(restore(text).encode()).hexdigest(),expected)
   verify(raw);self.assertIn(old,raw)
   for bad in (raw+'// unrelated source change\n',raw.replace(old,new,1)):
    with self.assertRaises(AssertionError):verify(bad)

 def test_exact_selector_inverse_preserves_p71_and_rejects_gate_or_scrub_mutations(self):
  import hashlib
  spec=importlib.util.spec_from_file_location('p72_selector_restoration',P.parent/'ci-financial-admit-read-source-audit.py');audit=importlib.util.module_from_spec(spec);spec.loader.exec_module(audit)
  raw=(P.parent.parent/'crates/wholepact-financial-coordinator/src/financial_source_ui.rs').read_text()
  raw=audit.restore_signing_retirement_ui(raw)
  raw=audit.restore_admission_scroll_ui(raw)
  self.assertEqual(hashlib.sha256(audit.restore_selector_export_ui(raw).encode()).hexdigest(),'930e2e54c6429bde08d5bddd6dc671c5a8b335777cb5e00bcc7763b6d11d5a27')
  for old,new in [('selector_export_phase(painted_phase)','selector_export_phase(self.phase)'),('!host_entry_blocks_source(host_entry) && has_selector','has_selector'),('self.retained_continue.iter().any(Option::is_some)','true'),('scrub_unrequested_payloads(&mut input.raw.events);','input.raw.events.clear();')]:
   self.assertIn(old,raw)
   with self.assertRaises(AssertionError):audit.restore_selector_export_ui(raw.replace(old,new,1))

 def test_exact_paired_scroll_inverse_preserves_p72_and_rejects_identity_or_completion_mutations(self):
  import hashlib
  spec=importlib.util.spec_from_file_location('p73_scroll_restoration',P.parent/'ci-financial-admit-read-source-audit.py');audit=importlib.util.module_from_spec(spec);spec.loader.exec_module(audit)
  raw=(P.parent.parent/'crates/wholepact-financial-coordinator/src/financial_source_ui.rs').read_text()
  raw=audit.restore_signing_retirement_ui(raw)
  self.assertEqual(hashlib.sha256(audit.restore_admission_scroll_ui(raw).encode()).hexdigest(),'a04c0d0394c63ffe1e93ca1a1f7295c570e5346576c9f018fc2f00dd8ffd88ce')
  for old,new in [('.id_salt(_ci_tag)','.id_salt("same")'),('.max_height(390.0)','.max_height(391.0)'),('eligible && ui.is_rect_visible(end.rect)','eligible')]:
   self.assertIn(old,raw)
   with self.assertRaises(AssertionError):audit.restore_admission_scroll_ui(raw.replace(old,new,1))

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

class RepaintExecutionPreflightTests(unittest.TestCase):
 def setUp(self):
  ContextPreflightTests.setUp(self)
  self.executable=self.target/'wholepact-financial-coordinator-test';self.executable.write_bytes(b'inert metadata fixture, never executed')
  row=next(r for r in self.rows if r.get('profile',{}).get('test') and r['manifest_path']==str(C.S.REPO/'crates/wholepact-financial-coordinator/Cargo.toml'))
  row.update(executable=str(self.executable),filenames=[str(self.executable)])
  self.index=self.rows.index(row)
 def check(self,rows):return C.coordinator_test_executable(b'\n'.join(json.dumps(x).encode() for x in rows),self.target)
 def test_exact_binary_features_cfg_and_pinned_test_inventory(self):
  self.assertEqual(self.check(self.rows),self.executable)
  self.assertEqual(C.REPAINT_TESTS,('financial_source_ui::repaint_tests::quiet_retirement_poll_requires_in_pass_repaint','financial_source_ui::repaint_tests::draw_poll_request_precedes_every_early_return'))
 def test_selector_export_exact_names_bind_to_actual_child_module(self):
  root=P.parent.parent;ui=root/'crates/wholepact-financial-coordinator/src/financial_source_ui.rs'
  self.assertIn('#[cfg(test)]\n#[path = "financial_source_ui/selector_export_tests.rs"]\nmod selector_export_tests;',ui.read_text())
  expected=('financial_source_ui::selector_export_tests::export_payloads_reach_focused_textedit_only_after_native_gate', 'financial_source_ui::selector_export_tests::export_input_gate_denies_wrong_phase_focus_revocation_host_and_missing_selector', 'financial_source_ui::selector_export_tests::export_payload_bounds_prevent_normalization_and_preserve_path_limit', 'financial_source_ui::selector_export_tests::export_routing_is_bound_to_native_fields_and_postpass_scrub')
  self.assertEqual(C.SELECTOR_EXPORT_TESTS,expected)
  child=ui.parent/'financial_source_ui/selector_export_tests.rs';source=child.read_text()
  import re
  self.assertEqual(set(re.findall(r'#\[test\]\s*fn (\w+)\s*\(',source)),{n.rsplit('::',1)[-1] for n in expected})
  self.assertNotIn('#[ignore]',source)
 def test_admission_scroll_exact_names_bind_to_actual_child_module(self):
  root=P.parent.parent;ui=root/'crates/wholepact-financial-coordinator/src/financial_source_ui.rs'
  self.assertIn('#[cfg(test)]\n#[path = "financial_source_ui/admission_scroll_tests.rs"]\nmod admission_scroll_tests;',ui.read_text())
  expected=('financial_source_ui::admission_scroll_tests::paired_review_scroll_areas_keep_independent_native_state', 'financial_source_ui::admission_scroll_tests::review_completion_requires_eligible_visible_end', 'financial_source_ui::admission_scroll_tests::paired_review_ids_and_completion_are_bound_to_production')
  self.assertEqual(C.ADMISSION_SCROLL_TESTS,expected)
  source=(ui.parent/'financial_source_ui/admission_scroll_tests.rs').read_text()
  import re
  self.assertEqual(set(re.findall(r'#\[test\]\s*fn (\w+)\s*\(',source)),{n.rsplit('::',1)[-1] for n in expected})
  self.assertNotIn('#[ignore]',source)
 def test_wrong_binary_features_profile_or_executable_rejected(self):
  for field,value in [('features',[]),('features',C.S.A.RECIPE['artifact_features']['coordinator-observed']+['extra']),('profile',dict(test=False)),('profile',dict(test=1)),('executable','/outside'),('filenames',[])]:
   rows=copy.deepcopy(self.rows);rows[self.index][field]=value
   with self.assertRaises(AssertionError):self.check(rows)
  for field,value in [('kind',['lib']),('name','other'),('src_path','/wrong/main.rs')]:
   rows=copy.deepcopy(self.rows);rows[self.index]['target'][field]=value
   with self.assertRaises(AssertionError):self.check(rows)
  with self.assertRaises(AssertionError):self.check(self.rows+[self.rows[self.index]])
  with self.assertRaises(AssertionError):self.check(self.rows[:self.index]+self.rows[self.index+1:])
  link=self.target/'linked-executable';link.symlink_to(self.executable)
  rows=copy.deepcopy(self.rows);rows[self.index].update(executable=str(link),filenames=[str(link)])
  with self.assertRaises(AssertionError):self.check(rows)
 def test_wrong_cfg_missing_script_and_output_escape_rejected(self):
  for field,value in [('cfgs',[]),('cfgs',list(C.S.A.FINANCIAL_CFGS[:2])),('linked_libs',['x']),('linked_paths',['/x']),('env',[['X','y']]),('out_dir','/')]:
   rows=copy.deepcopy(self.rows);rows[1][field]=value
   with self.assertRaises(AssertionError):self.check(rows)
  for rows in (self.rows[2:],self.rows+[self.rows[0]],self.rows+[dict(reason='build-script-executed',package_id='foreign',cfgs=['wholepact_financial_ci'])]):
   with self.assertRaises(AssertionError):self.check(rows)
 def test_no_run_then_exact_lists_and_runs_reject_missing_or_ignored_tests(self):
  from unittest import mock
  import contextlib,io
  names=C.REPAINT_TESTS+C.COORDINATOR_DIAGNOSTIC_TESTS+C.SELECTOR_EXPORT_TESTS+C.ADMISSION_SCROLL_TESTS+C.WITNESS_FIRST_FAILURE_TESTS+C.SIGNING_RETIREMENT_UI_TESTS;good='test result: ok. 1 passed; 0 failed; 0 ignored;'
  for listings,result,ok in [([n+': test\n' for n in names],good,True),(['']+[n+': test\n' for n in names[1:]],good,False),([n+': test\n' for n in names],'test result: ok. 0 passed; 0 failed; 1 ignored;',False)]:
   outputs=[b'compiler']+[x.encode() for x in listings]+[result.encode()]*len(names)
   with mock.patch.object(C.S,'select_build_environment',return_value={}),mock.patch.object(C,'coordinator_test_executable',return_value=self.executable),mock.patch.object(C,'run_provider_tls_probe',return_value=4) as probe,mock.patch.object(C.S,'checked',side_effect=outputs) as checked,contextlib.redirect_stdout(io.StringIO()):
    if ok:self.assertEqual(C.run_coordinator_tests(self.target,{}),12)
    else:
     with self.assertRaises(AssertionError):C.run_coordinator_tests(self.target,{})
    probe.assert_called_once_with(self.target,{},b'compiler')
    command=checked.call_args_list[0].args[0]
    self.assertIn('--no-run',command);self.assertIn('--locked',command);self.assertNotIn('--lib',command)
    self.assertEqual(command[command.index('--bin')+1],'wholepact-financial-coordinator')
    self.assertEqual(checked.call_args_list[0].kwargs['seconds'],900)
    for call in checked.call_args_list[1:]:self.assertLessEqual(call.kwargs['seconds'],30)
    if ok:
     self.assertEqual([call.args[0][1:] for call in checked.call_args_list[1:]],[[ '--list','--exact',n] for n in names]+[['--exact',n,'--test-threads=1'] for n in names])
 def test_origin_retirement_selector_matches_actual_module_path_in_both_profiles(self):
  root=P.parent.parent;origin=root/'crates/wholepact-financial-coordinator-origin/src'
  self.assertIn('mod financial_workflow_origin;', (origin/'lib.rs').read_text())
  self.assertIn('#[path="witness_retirement.rs"]\nmod retirement;', (origin/'financial_workflow_origin.rs').read_text())
  source=(origin/'witness_retirement.rs').read_text();self.assertIn('mod retirement_error_observation_tests {',source)
  name='history_retirement_observation_preserves_operation_and_original_io_error'
  self.assertIn('fn '+name+'()',source)
  workflow=(root/'.github/workflows/deadline-preflight.yml').read_text()
  self.assertEqual(workflow.count('financial_workflow_origin::retirement::retirement_error_observation_tests::'+name),2)
  self.assertNotIn('witness_retirement::retirement_error_observation_tests::',workflow)
 def test_actual_repaint_gate_precedes_broad_contexts_without_replacing_old_gates(self):
  text=P.read_text();main=text[text.index('def main():'):]
  self.assertLess(main.index('coordinator_executed=run_coordinator_tests(root,env)'),main.index("'cargo','check','--locked','--tests'"))
  for gate in ('validate(raw,','run_handoff_security_tests(','run_intent_validation_tests(','run_fixture_lifetime_tests(','check_signer_absence('):self.assertIn(gate,main)

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
  self.assertEqual(len(C.HANDOFF_SECURITY_TESTS),55)
  self.assertEqual(C.HANDOFF_SECURITY_TESTS[0],'native_ui::runtime::financial_v1::coordinated_v3_delivery::coordinated_delivery_admission_v1::ready_disconnect_tests::ready_disconnect_preserves_pending_worker_error_and_panic_without_fabricating_ready')
  self.assertEqual(len(C.INTENT_VALIDATION_TESTS),21)
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

class CompositionMeasurementTests(unittest.TestCase):
 def row(self,stage):return dict(stage=stage,**{k:123 for k in C.COMPOSITION_LENGTHS})
 def output(self,rows):return '\n'.join(C.COMPOSITION_MEASUREMENT_MARKER+json.dumps(v) for v in rows)
 def test_exact_three_domains_and_failure_prefix_only(self):
  self.assertEqual(list(C.COMPOSITION_MEASUREMENT_TESTS.values()),[('continue',),('sign_lower','sign'),('return_read','return_exact')])
  for name,stages in C.COMPOSITION_MEASUREMENT_TESTS.items():
   rows=[self.row(s) for s in stages]
   self.assertEqual(C.composition_measurement(name,self.output(rows),complete=True),rows)
   self.assertEqual(C.composition_measurement(name,self.output(rows[:1]),complete=False),rows[:1])
   if len(rows)>1:
    with self.assertRaises(AssertionError):C.composition_measurement(name,self.output(rows[:1]),complete=True)
 def test_bad_stages_records_and_values_fail_closed(self):
  name=next(n for n,v in C.COMPOSITION_MEASUREMENT_TESTS.items() if v==('sign_lower','sign'));base=self.row('sign_lower')
  cases=[[],[self.row('sign')],[base,base],[self.row('return_read')],[base,self.row('sign'),self.row('sign')]]
  for key,value in [('stage','unknown'),('stage',1),('display_bytes',True),('display_bytes',-1),('display_bytes',2*1024*1024+1),('display_bytes',float('nan')),('display_bytes',float('inf')),('display_bytes','1')]:
   row=dict(base);row[key]=value;cases.append([row])
  row=dict(base,payload='PRIVATE');cases.append([row])
  for rows in cases:
   with self.assertRaises(AssertionError):C.composition_measurement(name,self.output(rows),complete=False)
  for raw in (C.COMPOSITION_MEASUREMENT_MARKER+'{bad',C.COMPOSITION_MEASUREMENT_MARKER+'{"stage":"sign_lower","stage":"sign_lower"}',C.COMPOSITION_MEASUREMENT_MARKER+' '*1025+json.dumps(base)):
   with self.assertRaises(AssertionError):C.composition_measurement(name,raw,complete=False)
 def test_designated_failed_test_emits_only_safe_prefix_and_original_failure(self):
  from unittest import mock
  import contextlib,io
  name=next(n for n,v in C.COMPOSITION_MEASUREMENT_TESTS.items() if v==('sign_lower','sign'));rows=[self.row('sign_lower')]
  with tempfile.TemporaryDirectory() as td:
   error=C.S.Failure('compile','command_failed',('PRIVATE\n'+self.output(rows)).encode(),exit_status=101);error.cleanup_failed=True;captured=io.StringIO()
   with mock.patch.object(C,'INTENT_VALIDATION_TESTS',(name,)),mock.patch.object(C.S,'select_build_environment',return_value={}),mock.patch.object(C,'intent_test_executable',return_value=pathlib.Path(td)/'testbin'),mock.patch.object(C.S,'checked',side_effect=[b'compiler',(name+': test\n').encode(),error]) as checked,contextlib.redirect_stdout(captured):
    with self.assertRaises(C.S.Failure) as caught:C.run_intent_validation_tests(pathlib.Path(td),{})
   self.assertIs(caught.exception,error);self.assertEqual(error.output,b'');self.assertEqual(error.exit_status,101);self.assertTrue(error.cleanup_failed);self.assertIn('--nocapture',checked.call_args_list[-1].args[0])
   self.assertNotIn('PRIVATE',captured.getvalue());value=json.loads(captured.getvalue().split('CI_COMPOSITION_SIZE_V1 ',1)[1]);self.assertEqual(value,dict(test=name,complete=False,test_passed=False,records=rows))

class OriginalFailureSelectionTests(unittest.TestCase):
 def test_exact_p75_inverse_restores_p74_and_rejects_any_source_mutation(self):
  import hashlib
  spec=importlib.util.spec_from_file_location('p75r_original_failure_audit',P.parent/'ci-financial-admit-read-source-audit.py');audit=importlib.util.module_from_spec(spec);spec.loader.exec_module(audit)
  paths={'observer':'wholepact-financial-coordinator-origin/src/financial_observer.rs','origin_actor':'wholepact-financial-coordinator-origin/src/financial_ci_actor_diagnostics.rs','signer_actor':'wholepact-signer/src/financial_ci_actor.rs'}
  expected={'observer':'d29ce563717f0a53e0406a49d552688fe69a829f4dfb0437fa4f3dbfa15910f5','origin_actor':'e76f5886ae5bf83e183bd1186e5ac58af8c7b7d2b946b5ae23a6e538edf2103e','signer_actor':'69c786b0c086c6fa2b9747a62a3327291a6f3bbe97039ea1b602d95d35394581'}
  self.assertEqual(set(audit.P75_FAILURE_CAUSE_INVERSES),set(paths))
  for kind,path in paths.items():
   raw=(P.parent.parent/'crates'/path).read_text();pin=audit.P75_FAILURE_CAUSE_INVERSES[kind]
   self.assertEqual(hashlib.sha256(raw.encode()).hexdigest(),pin['candidate_sha256']);self.assertEqual(pin['baseline_sha256'],expected[kind])
   self.assertEqual(hashlib.sha256(audit.restore_original_failure_cause(raw,kind).encode()).hexdigest(),expected[kind])
   self.assertTrue(pin['pairs'])
   for remove,restore in pin['pairs']:
    self.assertNotEqual(remove,restore);self.assertEqual(raw.count(remove),1)
    with self.assertRaises(AssertionError):audit.restore_original_failure_cause(raw.replace(remove,restore,1),kind)
   for mutation in (raw+'\n','// changed\n'+raw,raw.replace('pub(crate)','pub',1)):
    self.assertNotEqual(mutation,raw)
    with self.assertRaises(AssertionError):audit.restore_original_failure_cause(mutation,kind)

 def test_new_native_selections_bind_existing_binaries_and_real_functions(self):
  groups=[(C.HANDOFF_SECURITY_TESTS,55),(C.INTENT_VALIDATION_TESTS,21),(tuple(n for v in C.FIXTURE_TARGETS.values() for n in v[-1]),20)]
  for names,count in groups:self.assertEqual(len(names),count);self.assertEqual(len(set(names)),count)
  prefix='native_ui::runtime::financial_v1::coordinated_driver::financial_tail_v1::financial_worker_observation_tests::'
  checks=[(C.HANDOFF_SECURITY_TESTS,prefix+'actual_join_preserves_worker_error_identity_and_success','wholepact-signer/src/native_ui/runtime/coordinated_financial_driver_v1/financial_tail_v1.rs'),(C.HANDOFF_SECURITY_TESTS,prefix+'actual_join_panic_remains_uncertain_without_retry','wholepact-signer/src/native_ui/runtime/coordinated_financial_driver_v1/financial_tail_v1.rs'),(C.HANDOFF_SECURITY_TESTS,'native_ui::witness_workspace::financial_continuation_v1::coordinated_admit_v1::tests::failed_admit_observation_retains_actual_cause_and_transport_boundary','wholepact-signer/src/native_ui/witness_workspace/financial_continuation_v1/coordinated_admit_v1.rs'),(C.HANDOFF_SECURITY_TESTS,'financial_ci_actor::admit_transport_plain_observation_tests::plain_admission_result_retains_success_and_original_error_variants','wholepact-signer/src/financial_ci_actor.rs'),(C.INTENT_VALIDATION_TESTS,'financial_ci_actor::admit_transport_observation_tests::checked_admission_stages_and_callback_precedence_are_finite','wholepact-signer/src/financial_ci_actor.rs'),(C.FIXTURE_TARGETS['authority'][-1],'transport::history_diagnostics_v1::tests::pure_flow_frame_first_error_and_returned_error_remain_independent','wholepact-authority/src/transport/history_diagnostics_v1.rs'),(C.WITNESS_FIRST_FAILURE_TESTS,'financial_source_driver::reported_witness_failure_tests::authenticated_report_projection_retains_every_finite_stage_class_and_peer','wholepact-financial-coordinator/src/financial_source_driver.rs')]
  self.assertEqual(len(C.WITNESS_FIRST_FAILURE_TESTS),1)
  for names,name,path in checks:
   self.assertEqual(names.count(name),1)
   self.assertIn('fn '+name.rsplit('::',1)[-1]+'(', (P.parent.parent/'crates'/path).read_text())
  self.assertEqual(len(C.REPAINT_TESTS+C.COORDINATOR_DIAGNOSTIC_TESTS+C.SELECTOR_EXPORT_TESTS+C.ADMISSION_SCROLL_TESTS+C.WITNESS_FIRST_FAILURE_TESTS+C.SIGNING_RETIREMENT_UI_TESTS),12)

 def test_cause_trace_is_mandatory_and_all_semantic_reporters_are_executed(self):
  import ast,re
  workflow=(P.parent.parent/'.github/workflows/deadline-preflight.yml').read_text()
  command="print(run(rustup+['python3', '-I', '-B', 'scripts/ci-financial-cause-trace.py'], env=env, timeout=180))"
  self.assertEqual(workflow.count(command),1)
  self.assertLess(workflow.index("assert run(rustup+['rustc', '--version']"),workflow.index(command))
  self.assertLess(workflow.index(command),workflow.index("rustup+['cargo'"))
  self.assertNotIn('--source-only',workflow)
  names=ast.literal_eval(re.search(r'semantic_names = (\[.*?\])',workflow,re.S).group(1))
  self.assertEqual(len(names),9);self.assertEqual(len(set(names)),9)
  required={'financial_ci_actor_diagnostics::tests::coordinator_reported_witness_detail_precedes_cascading_peer_exit':'financial_ci_actor_diagnostics.rs','financial_ci_host_diagnostics::tests::relay_top_level_failure_preserves_inner_observation_and_first_failure':'financial_ci_host_diagnostics.rs','financial_ci_host_diagnostics::tests::copied_reporter_records_panicking_or_failed_append_before_second_flush':'financial_ci_host_diagnostics.rs','financial_observer::early_actor_observation_tests::host_pre_drop_flush_never_waits_for_owned_writer_lock':'financial_observer.rs'}
  for name,path in required.items():
   self.assertIn(name,names)
   self.assertIn('fn '+name.rsplit('::',1)[-1]+'(', (P.parent.parent/'crates/wholepact-financial-coordinator-origin/src'/path).read_text())
  gate=workflow.split('for name in semantic_names:',1)[1].split('print(',1)[0]
  for token in ("'--list', '--exact'","'--exact', name, '--test-threads=1'",'1 passed; 0 failed; 0 ignored;'):self.assertIn(token,gate)

class FinancialContinuationReplaySelectionTests(unittest.TestCase):
 def test_existing_authority_target_executes_both_actual_journal_regressions(self):
  expected=('journal::durable_financial_continuation_journal_v1::tests::coordinated_final_stamp_uses_financial_profile_without_weakening_replay','journal::durable_financial_continuation_journal_v1::tests::coordinated_final_stamp_is_bound_to_the_post_append_phase')
  crate,features,scripts,names=C.FIXTURE_TARGETS['authority']
  self.assertEqual(crate,'wholepact-authority');self.assertIn('native-witness-owner',features)
  self.assertNotIn('coordinated-witness-financial-continuation',features)
  self.assertEqual(names[-2:],expected);self.assertEqual(len(names),12)
  self.assertEqual(len(C.FIXTURE_TARGETS['pristine-host'][-1]),8)
  root=P.parent.parent/'crates/wholepact-authority/src'
  source=(root/'durable_financial_continuation_journal_v1.rs').read_text()
  for name in expected:self.assertEqual(source.count('fn '+name.rsplit('::',1)[-1]+'('),1)
  self.assertIn('#[cfg(all(feature = "native-witness-owner", target_os = "linux"))]\n#[path = "durable_financial_continuation_journal_v1.rs"]\nmod durable_financial_continuation_journal_v1;', (root/'journal.rs').read_text())

class SigningRetirementSelectorPreflightTests(unittest.TestCase):
 def test_actual_selector_guard_has_exact_ui_inverse_and_native_execution_binding(self):
  import hashlib
  spec=importlib.util.spec_from_file_location('p77_signing_ui_audit',P.parent/'ci-financial-admit-read-source-audit.py');audit=importlib.util.module_from_spec(spec);spec.loader.exec_module(audit)
  raw=(P.parent.parent/'crates/wholepact-financial-coordinator/src/financial_source_ui.rs').read_text()
  self.assertEqual(hashlib.sha256(audit.restore_signing_retirement_ui(raw).encode()).hexdigest(),'564479de74dffffc910e0860a6b51100270fb31fa197de30dcdcccc148946ab6')
  for old,new in [('self.result_selectors[index(role)].is_some()','true'),('later_frame && selector_present','later_frame'),('data.actor.signer_role != role','false')]:
   self.assertIn(old,raw)
   with self.assertRaises(AssertionError):audit.restore_signing_retirement_ui(raw.replace(old,new,1))
  name='financial_source_ui::signing_retirement_action_tests::signing_retirement_requires_actual_commit_and_fresh_explicit_action'
  self.assertEqual(C.SIGNING_RETIREMENT_UI_TESTS,(name,));self.assertEqual(raw.count('fn '+name.rsplit('::',1)[-1]+'('),1)
  self.assertIn('mod signing_retirement_action_tests {',raw)

class ProviderTlsProbeGateTests(unittest.TestCase):
 def test_exact_four_cases_are_mandatory_after_metadata_before_existing_test_budget(self):
  from unittest import mock
  import inspect,types
  raw=b'inert compiler metadata';env={'bounded':'build'};root=pathlib.Path('/inert-owned-target')
  for value in (4,3,5,True,None):
   spec=types.SimpleNamespace(loader=mock.Mock());module=types.SimpleNamespace(run=mock.Mock(return_value=value))
   with mock.patch.object(C.importlib.util,'spec_from_file_location',return_value=spec) as make,mock.patch.object(C.importlib.util,'module_from_spec',return_value=module):
    if type(value) is int and value==4:self.assertEqual(C.run_provider_tls_probe(root,env,raw),4)
    else:
     with self.assertRaises(AssertionError):C.run_provider_tls_probe(root,env,raw)
    make.assert_called_once_with('preflight_provider_tls_probe',C.HERE/'ci-financial-provider-tls-probe.py');spec.loader.exec_module.assert_called_once_with(module);module.run.assert_called_once_with(root,env,raw,C.S)
  source=inspect.getsource(C.run_coordinator_tests)
  self.assertLess(source.index('executable=coordinator_test_executable('),source.index('run_provider_tls_probe(root,selected,raw)'))
  self.assertLess(source.index('run_provider_tls_probe(root,selected,raw)'),source.index('deadline=time.monotonic()+60'))
  self.assertEqual(source.count('run_provider_tls_probe('),1)

class ResultSelectorDomainPreflightTests(unittest.TestCase):
 def test_existing_production_origin_executes_all_actual_selector_domain_regressions(self):
  import ast,re
  root=P.parent.parent
  workflow=(root/'.github/workflows/deadline-preflight.yml').read_text()
  expected=('actual_selector_preserves_closed_request_and_original_endpoint', 'selector_cannot_replace_result_source_or_socket', 'selector_cannot_replace_fixed_authorization_consent_or_account', 'selector_rejects_unknown_request_fields_and_relative_or_control_paths', 'distinct_financial_and_delivery_sources_join_without_relabelling', 'selector_binds_each_original_v3_observation_field_independently', 'selector_join_is_bound_to_actual_source_domains_and_retained_callers')
  marker="          names += ['financial_workflow_origin::financial_selector::tests::'+n for n in "
  lines=[line for line in workflow.splitlines() if line.startswith(marker)]
  self.assertEqual(len(lines),1)
  self.assertEqual(tuple(ast.literal_eval(lines[0][len(marker):-1])),expected)
  self.assertEqual(len(expected),7);self.assertEqual(len(set(expected)),7)
  origin=root/'crates/wholepact-financial-coordinator-origin/src'
  self.assertIn('#[cfg(feature = "coordinated-financial-workflow-v1")]\nmod financial_workflow_origin;', (origin/'lib.rs').read_text())
  self.assertIn('#[path="financial_selector_origin.rs"]\nmod financial_selector;', (origin/'financial_workflow_origin.rs').read_text())
  source=(origin/'financial_selector_origin.rs').read_text()
  self.assertIn('#[cfg(test)]\nmod tests {',source)
  self.assertEqual(tuple(re.findall(r'#\[test\]\s+fn (\w+)\(',source)),expected)
  for name in expected:self.assertEqual(source.count('fn '+name+'('),1)
  self.assertEqual(workflow.count('assert len(names) == 26 and len(set(names)) == 26'),1)
  self.assertLess(workflow.index("env = environments['production']"),workflow.index(marker))
  self.assertLess(workflow.index(marker),workflow.index("env = environments['observed-semantic']"))
  gate=workflow.split('          for name in names:',1)[1].split('          # These actual Origin',1)[0]
  for token in ("'--list', '--exact'","'--exact', name, '--test-threads=1'",'1 passed; 0 failed; 0 ignored;','timeout=30'):self.assertIn(token,gate)
