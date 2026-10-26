"""Actual FullFlow.run/seek/press + NativeScenario, inert clipping only.

No Window, native custody, retirement permission or runtime-cause claim.
"""
import contextlib
import io
import json
import importlib.util
import pathlib
import sys
import tempfile
import time
import unittest
from unittest import mock

ROOT=pathlib.Path(__file__).resolve().parents[1]
spec=importlib.util.spec_from_file_location('park_navigation_flow',ROOT/'ci-financial-flow.py')
F=importlib.util.module_from_spec(spec);sys.modules[spec.name]=F;spec.loader.exec_module(F)
class ClickReached(Exception):pass

class ParkNavigationTests(unittest.TestCase):
 def model(self,owner='Signer1',profile=None,phase='SignedRetired',case='recover',seed=0,module=None):
  m=module or F;profile=profile or m.C.SEMANTIC_PROFILE
  directory=tempfile.TemporaryDirectory();self.addCleanup(directory.cleanup)
  public=pathlib.Path(directory.name)/'inert-retained-selector';public.write_text('{}\n')
  state=dict(frame=0,wheels=0,bounds=[],error=OSError('inert effect failure'))
  controller=mock.Mock();fixture=mock.Mock(deadline_ns=time.monotonic_ns()+300_000_000_000)
  fixture.source_path.return_value=str(public);observer=mock.Mock(expected_profile=profile);observer.read.return_value=[]
  def next_snapshot(bound):
   state['frame']+=1;g=state['frame'];state['bounds'].append(bound)
   if g>210:raise AssertionError('inert observation bound')
   present=(g%3==1 if case=='oscillate' else g==1 or state['wheels']>0)
   if case in ('visible','disabled','click_error','wait_error','sibling_widget','unowned_widget'):present=True
   if case=='changing':present=g!=3
   widgets=[dict(tag='ScrollRegion',owner=None,enabled=True,rect=[0,0,1280,800])]
   if present:widgets.append(dict(tag='ParkFinancial',owner=owner,enabled=not(case=='disabled' and g>=2),rect=[20,760,300,790]))
   row=dict(phase=phase,subphase='None',owner=owner,view_generation=g,focused=True,
       secret_input=False,host_input=False,pixels_per_point=1,viewport=[1280,800],widgets=widgets,
       host_observation=dict(revision=1,nonws_end=0,context_valid=True,entry='Idle',editor=None,view=None))
   if g>=2:
    if case=='wrong_owner':row['owner']='Signer2' if owner=='Signer1' else 'Signer1'
    if case=='sibling_widget':widgets[-1]['owner']='Signer2' if owner=='Signer1' else 'Signer1'
    if case=='unowned_widget':widgets[-1]['owner']=None
    if case=='wrong_phase':row['phase']='SignCommitted'
    if case=='subphase':row['subphase']='Acquiring'
    if case=='scale':row['pixels_per_point']=2
    if case=='viewport':row['viewport']=[1280,900]
    if case=='revision':row['host_observation']['revision']=2
    if case=='end':row['host_observation']['nonws_end']=1
    if case=='context':row['host_observation']['context_valid']=False
    if case=='writing':row['host_observation']['entry']='Writing'
    if case=='unfocused':row['focused']=False
    if case=='protected':row['secret_input']=True
    if case=='invalid_rect':widgets[0]['rect']=[0,0,0,0]
   if profile==m.C.SEMANTIC_PROFILE:row['host_view_id']=None
   return row
  observer.next_snapshot.side_effect=next_snapshot
  flow=m.FullFlow(controller,fixture,observer,None)
  flow.startup_index=13;flow.startup_focus_seen=True;flow.commands_instruction_observed=True;flow._startup_ceiling=None
  flow.last_phase=(phase,'None',owner);flow.scrolls[(phase,'None','seek','ParkFinancial',owner)]=seed
  def wheel(*point):state['wheels']+=1
  controller.scroll_up.side_effect=controller.scroll_down.side_effect=wheel
  controller.click.side_effect=state['error'] if case=='click_error' else ClickReached()
  if case=='wait_error':
   controller.click.side_effect=None
   def wait():
    if controller.click.call_count:raise state['error']
   controller.wait_render_progress.side_effect=wait
  return flow,controller,state
 def test_actual_direct_reseeks_only_stably_missing_park_before_effect(self):
  for profile in (F.C.PROFILE,F.C.EXTERNAL_PROFILE,F.C.SEMANTIC_PROFILE):
   for owner in ('Signer1','Signer2'):
    for phase in ('SignedRetired','ReturnCompleted'):
     for case in ('recover','visible'):
      with self.subTest(profile=profile,owner=owner,phase=phase,case=case):
       f,c,s=self.model(owner,profile,phase,case)
       with self.assertRaises(ClickReached):f.run()
       self.assertEqual(s['wheels'],case=='recover');self.assertEqual(c.click.call_count,1)
       self.assertEqual(f.actions,1);self.assertEqual(len(f.done),1);c.type_ascii.assert_not_called()
       self.assertTrue(all(v==f.fixture.deadline_ns for v in s['bounds']))
 def test_original_disabled_stable_context_and_geometry_guards_remain_fatal(self):
  for owner in ('Signer1','Signer2'):
   for case in ('disabled','changing','wrong_owner','sibling_widget','unowned_widget','wrong_phase','subphase','scale','viewport',
                'revision','end','context','writing','unfocused','protected','invalid_rect'):
    with self.subTest(owner=owner,case=case):
     f,c,s=self.model(owner,case=case)
     with self.assertRaises(F.C.Rejected) as caught:f.run()
     if case=='disabled':self.assertEqual(caught.exception.code,'input_disabled')
     self.assertEqual(s['wheels'],0);c.click.assert_not_called();self.assertEqual(f.actions,0);self.assertFalse(f.done)
  for pending in ('pending_host','host_prepared'):
   f,c,s=self.model();frame=f.snapshot();setattr(f,pending,object())
   with self.assertRaises(F.C.Rejected):f.press(frame,'ParkFinancial','Signer1',park_reseek=True)
   self.assertEqual(s['wheels'],0);c.click.assert_not_called();self.assertFalse(f.done)
 def test_repeated_missing_frames_spend_original_seek_budget_and_keep_direction(self):
  for seed in (0,24,63,64):
   f,c,s=self.model(case='oscillate',seed=seed)
   with self.assertRaises(F.C.Rejected) as caught:f.run()
   self.assertEqual(caught.exception.code,'input_widget')
   self.assertEqual(s['wheels'],64-seed);self.assertEqual(f.scrolls[('SignedRetired','None','seek','ParkFinancial','Signer1')],65)
   self.assertEqual(c.scroll_up.call_count,max(0,24-seed));self.assertEqual(c.scroll_down.call_count,64-max(24,seed))
   self.assertEqual(f.actions,0);self.assertFalse(f.done);c.click.assert_not_called()
  f,c,s=self.model();f.scrolls[('SignedRetired','None','ScrollRegion',None,'up')]=128
  with self.assertRaises(F.C.Rejected) as caught:f.run()
  self.assertEqual(caught.exception.code,'input_budget');self.assertEqual(s['wheels'],0);self.assertFalse(f.done)
  f,c,s=self.model();f.fixture.deadline_ns=time.monotonic_ns()-1
  with self.assertRaises(F.C.Rejected) as caught:f.run()
  self.assertEqual(caught.exception.code,'deadline');self.assertEqual(s['wheels'],0);c.click.assert_not_called();self.assertFalse(f.done)
 def test_post_effect_errors_and_unopted_calls_are_never_retried(self):
  for case in ('click_error','wait_error'):
   f,c,s=self.model(case=case)
   with self.assertRaises(OSError) as caught:f.run()
   self.assertIs(caught.exception,s['error']);self.assertEqual(c.click.call_count,1)
   self.assertEqual(f.actions,1);self.assertEqual(len(f.done),1);self.assertEqual(s['wheels'],0)
   with self.assertRaises(F.C.Rejected) as replay:f.press(f.snapshot(),'ParkFinancial','Signer1',park_reseek=True)
   self.assertEqual(replay.exception.code,'replay');self.assertEqual(c.click.call_count,1)
  f,c,s=self.model();frame=f.snapshot()
  with self.assertRaises(F.C.Rejected) as caught:f.press(frame,'ParkFinancial','Signer1')
  self.assertEqual(caught.exception.code,'input_disabled');self.assertEqual(s['wheels'],0);self.assertFalse(f.done)
 def test_closed_callsite_matches_native_park_render_and_original_tail(self):
  source=(ROOT/'ci-financial-flow.py').read_text();ui=(ROOT.parent/'crates/wholepact-financial-coordinator/src/financial_source_ui.rs').read_text()
  self.assertEqual(source.count("{'park_reseek':True}"),1)
  self.assertIn("if action=='ParkFinancial' and phase in ('SignedRetired','ReturnCompleted')",source)
  self.assertIn("self.seek(latest,tag,owner)\n            return\n",source)
  self.assertIn('matches!(self.phase,Phase::SignedRetired|Phase::ReturnCompleted)',ui)
  self.assertIn('"ParkFinancial", self.active',ui)
  self.assertIn('Intent::ParkFinancial\n                if financial_park_eligible(',ui)
  self.assertIn('financial_park_eligible(',ui)
  self.assertIn('ScrollArea::vertical().id_salt("financial-ci-full-panel")',ui)
  geometry=(ROOT.parent/'crates/wholepact-financial-coordinator/src/financial_ci.rs').read_text()
  self.assertIn('intersect',geometry);self.assertIn('is_positive()',geometry)

class InputGuardDiagnosticTests(unittest.TestCase):
 model=ParkNavigationTests.model
 # Reuse only the inert actual-flow fixture, not its test methods.
 def setUp(self):
  def load(name):
   spec=importlib.util.spec_from_file_location('park_'+name,ROOT/(name+'.py'))
   m=importlib.util.module_from_spec(spec);sys.modules[spec.name]=m;spec.loader.exec_module(m);return m
  self.container=load('ci-financial-container');self.supervisor=load('ci-financial-supervisor')
 def value(self,status='Missing'):
  return dict(version=2,guard=dict(phase='SignedRetired',subphase='None',owner='Signer1',target_owner='Signer1',
      tag='ParkFinancial',view_generation=3,status=status))
 def line(self,value):return b'CI_FINANCIAL_INPUT_DIAGNOSTIC '+json.dumps(value).encode()
 def test_fresh_failure_frame_metadata_and_exception_identity(self):
  for status,case,optin in [('Disabled','disabled',True),('Missing','recover',False)]:
   f,c,s=self.model(case=case);frame=f.snapshot();error=F.C.Rejected('input_disabled');original=F.C.require
   def require(ok,code='record_shape'):
    if not ok and code=='input_disabled':raise error
    return original(ok,code)
   with mock.patch.object(F.C,'require',side_effect=require):
    with self.assertRaises(F.C.Rejected) as caught:f.press(frame,'ParkFinancial','Signer1',park_reseek=optin)
   self.assertIs(caught.exception,error);self.assertEqual(error.input_guard,self.value(status)['guard'])
   c.click.assert_not_called();self.assertFalse(f.done)
  class Unannotatable(F.C.Rejected):
   def __setattr__(self,key,value):
    if key=='input_guard':raise ValueError('inert attribution failure')
    super().__setattr__(key,value)
  f,c,s=self.model(case='disabled');frame=f.snapshot();error=Unannotatable('input_disabled');original=F.C.require
  def require(ok,code='record_shape'):
   if not ok and code=='input_disabled':raise error
   return original(ok,code)
  with mock.patch.object(F.C,'require',side_effect=require):
   with self.assertRaises(F.C.Rejected) as caught:f.press(frame,'ParkFinancial','Signer1',park_reseek=True)
  self.assertIs(caught.exception,error);self.assertFalse(hasattr(error,'input_guard'));c.click.assert_not_called()
 def test_closed_versioned_schema_and_no_diagnostic_reads_or_error_replacement(self):
  for status in ('Missing','Disabled'):self.assertEqual(F.C.validate_input_diagnostic(self.value(status)),self.value(status))
  for key,value in [('tag','private text'),('phase','invented'),('subphase','invented'),('owner','Host'),
                    ('target_owner','Host'),('view_generation',True),('view_generation',0),('status','Enabled')]:
   bad=self.value();bad['guard'][key]=value
   with self.assertRaises(F.C.Rejected):F.C.validate_input_diagnostic(bad)
  bad=self.value();bad['guard']['rect']=[0,0,1,1]
  with self.assertRaises(F.C.Rejected):F.C.validate_input_diagnostic(bad)
  error=F.C.Rejected('input_disabled');error.input_guard=self.value()['guard'];flow=mock.Mock();out=io.StringIO()
  with contextlib.redirect_stdout(out):self.container.emit_cached_input_failure(flow,error)
  self.assertEqual(json.loads(out.getvalue().split(' ',1)[1]),self.value());self.assertFalse(flow.mock_calls)
  with mock.patch('builtins.print',side_effect=BrokenPipeError('inert output failure')):
   self.container.emit_cached_input_failure(flow,error)
  for code in ('input_phase','snapshot'):
   error=F.C.Rejected(code);error.input_guard=self.value()['guard'];out=io.StringIO()
   with contextlib.redirect_stdout(out):self.container.emit_cached_input_failure(flow,error)
   self.assertEqual(out.getvalue(),'')
  error=F.C.Rejected('input_disabled');error.input_guard={'private':'not valid'};out=io.StringIO()
  with contextlib.redirect_stdout(out):self.container.emit_cached_input_failure(flow,error)
  self.assertEqual(out.getvalue(),'')
 def test_supervisor_failure_code_version_and_terminal_gates(self):
  S=self.supervisor
  legacy=dict(version=1,budget=dict(site='idle_sweep',count=64,limit=64),last_main_loop=None)
  candidate=dict(schema=1,profile=S.P.C.EXTERNAL_PROFILE,native_oracle_verified=True,fixture_cleaned=True,
                 display_cleaned=True,public_chain_verified=False,dispatch_attempted=False)
  for value,code in [(legacy,'input_budget'),(self.value(),'input_disabled')]:
   r=S.RuntimeRecords('external');out=io.StringIO()
   with contextlib.redirect_stdout(out):r(self.line(value))
   self.assertEqual(out.getvalue(),'')
   with self.assertRaises(S.Failure):r(self.line(value))
   with contextlib.redirect_stdout(out):r(b'CI_FINANCIAL_RESULT '+json.dumps(S.P.failure(code)).encode())
   self.assertIn('CI_FINANCIAL_INPUT_DIAGNOSTIC ',out.getvalue())
   with self.assertRaises(S.Failure):r(self.line(value))
   for wrong in ('input_phase','input_disabled' if code=='input_budget' else 'input_budget'):
    r=S.RuntimeRecords('external');r(self.line(value))
    with self.assertRaises(S.Failure):r(b'CI_FINANCIAL_RESULT '+json.dumps(S.P.failure(wrong)).encode())
   r=S.RuntimeRecords('external');r(self.line(value))
   with self.assertRaises(S.Failure):r(b'CI_FINANCIAL_CANDIDATE '+json.dumps(candidate).encode())
   r=S.RuntimeRecords('external')
   with contextlib.redirect_stdout(io.StringIO()):r(b'CI_FINANCIAL_CANDIDATE '+json.dumps(candidate).encode())
   with self.assertRaises(S.Failure):r(self.line(value))
  r=S.RuntimeRecords('external');r(self.line(self.value()));failure=S.P.failure('input_disabled');seen=[]
  def emit(kind,value):
   if kind=='INPUT_DIAGNOSTIC':raise BrokenPipeError('inert diagnostic failure')
   seen.append((kind,value))
  with mock.patch.object(S,'emit',side_effect=emit):r(b'CI_FINANCIAL_RESULT '+json.dumps(failure).encode())
  self.assertEqual(r.result,failure);self.assertEqual(seen,[('FAILURE',failure)])

if __name__=='__main__':unittest.main()
