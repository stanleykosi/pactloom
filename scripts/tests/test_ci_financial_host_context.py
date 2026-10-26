import copy
import importlib.util
import pathlib
import unittest
ROOT=pathlib.Path(__file__).resolve().parents[1]
def load(name):
    s=importlib.util.spec_from_file_location(name,ROOT/(name+'.py'));m=importlib.util.module_from_spec(s);s.loader.exec_module(m);return m
H=load('ci-financial-host-context'); C=load('ci-financial-contract')
PROMPT=H.PROMPTS[12]
def observation(text,revision=1,end=None):
    return dict(revision=revision,nonws_end=H.count(text) if end is None else end,context_valid=True,entry='Idle',editor=None,view=dict(rect=[10,10,600,230],nonws=H.count(text),rows=4))
def snapshot(h):
    return dict(phase='Selecting',subphase='None',owner=None,view_generation=1,focused=True,secret_input=False,host_input=False,pixels_per_point=1,viewport=[1280,800],widgets=[dict(tag='HostOutput',owner=None,enabled=True,rect=[0,0,640,240])],host_observation=h)
class HostContextTests(unittest.TestCase):
    def test_all_source_literal_suffixes(self):
        for prompt in H.PROMPTS:
            with self.subTest(prompt_index=H.PROMPTS.index(prompt)):
                occurrence,text=H.HostOccurrences().inspect(prompt,observation(prompt))
                self.assertEqual(occurrence[:2],(0,H.count(prompt)))
    def test_same_line_repeated_text_is_distinct_occurrence(self):
        ledger=H.HostOccurrences();a,_=ledger.inspect(PROMPT,observation(PROMPT));ledger.latch(a)
        b,_=ledger.inspect(PROMPT,observation(PROMPT,2,2*H.count(PROMPT)));ledger.latch(b)
        self.assertEqual(b[:2],(a[1],2*a[1]))
    def test_prefix_change_or_retirement_cannot_renew_old_prompt(self):
        ledger=H.HostOccurrences();text='old prefix '+PROMPT;a,_=ledger.inspect(text,observation(text));ledger.latch(a)
        with self.assertRaisesRegex(H.HostContextRejected,'host_occurrence_replay'):
            ledger.inspect(PROMPT,observation(PROMPT,2,a[1]))
    def test_whitespace_only_append_does_not_renew(self):
        ledger=H.HostOccurrences();a,_=ledger.inspect(PROMPT,observation(PROMPT));ledger.latch(a)
        with self.assertRaisesRegex(H.HostContextRejected,'host_occurrence_replay'):
            ledger.inspect(PROMPT+' \n\t',observation(PROMPT+' \n\t',2))
    def test_unrelated_nonwhite_append_does_not_reuse_old_prompt(self):
        text=PROMPT+'unrelated'
        with self.assertRaisesRegex(H.HostContextRejected,'host_capture_grammar'):H.HostOccurrences().inspect(text,observation(text,2))
    def test_partial_prompt_and_changed_ocr_fail_closed(self):
        for text in (PROMPT[:-15],PROMPT+'x'):
            with self.assertRaises(H.HostContextRejected):H.HostOccurrences().inspect(text,observation(PROMPT))
        h=observation(PROMPT);h['view']['nonws']+=1
        with self.assertRaisesRegex(H.HostContextRejected,'host_capture_count'):H.HostOccurrences().inspect(PROMPT,h)
    def test_exact_complete_approval_no_repair(self):
        text='Type APPROVE 0123456789abcdef to approve this exact operation, or anything else to reject: '
        H.HostOccurrences().inspect(text,observation(text))
        for bad in (text.replace('APPROVE','APPR0VE'),text.replace('cdef','cdeg'),text.replace('89ab','89\nab'),text.split(',')[0]+','):
            with self.assertRaisesRegex(H.HostContextRejected,'host_capture_grammar'):H.HostOccurrences().inspect(bad,observation(bad))
    def test_real_wrap_whitespace_between_tokens_only(self):
        text=PROMPT.replace(' ', '\n')
        H.HostOccurrences().inspect(text,observation(text))
        self.assertEqual(H.count(text),H.count(PROMPT))
    def test_protected_or_invalid_context_refuses(self):
        for state in ('Editing','Writing','Closed'):
            h=observation(PROMPT);h['entry']=state;h['view']=None
            with self.assertRaises(H.HostContextRejected):H.HostOccurrences().inspect(PROMPT,h)
        h=observation(PROMPT);h['context_valid']=False
        with self.assertRaises(H.HostContextRejected):H.HostOccurrences().inspect(PROMPT,h)
    def test_entry_stamp_change_and_writing_refuse(self):
        h=observation(PROMPT);occ,_=H.HostOccurrences().inspect(PROMPT,h)
        h.update(entry='Editing',editor=dict(ordinal=1,revision=1),view=None)
        self.assertTrue(H.HostOccurrences.editor_matches(occ,h))
        h['revision']=2;self.assertFalse(H.HostOccurrences.editor_matches(occ,h))
        h['revision']=1;h['entry']='Writing';self.assertFalse(H.HostOccurrences.editor_matches(occ,h))
    def test_fixed_bounds_schema_and_no_sensitive_fields(self):
        h=observation(PROMPT);C.validate_snapshot(snapshot(h))
        for key,value in (('revision',262145),('nonws_end',1048577),('raw_text','forbidden'),('context_valid',1)):
            bad=copy.deepcopy(h);bad[key]=value
            with self.assertRaises(C.Rejected):C.validate_snapshot(snapshot(bad))
        for key,value in (('nonws',8193),('rows',33),('rect',[-1,10,600,230])):
            bad=copy.deepcopy(h);bad['view'][key]=value
            with self.assertRaises(C.Rejected):C.validate_snapshot(snapshot(bad))
    def test_monotonic_observation_and_finite_attempts(self):
        ledger=H.HostOccurrences();ledger.inspect(PROMPT,observation(PROMPT,3))
        with self.assertRaises(H.HostContextRejected):ledger.inspect(PROMPT,observation(PROMPT,2))
        ledger.attempts=128
        with self.assertRaises(H.HostContextRejected):ledger.latch((0,5,1))
    def test_ascii_and_capture_caps(self):
        for text in ('é'+PROMPT,' '*8193+PROMPT):
            with self.assertRaisesRegex(H.HostContextRejected,'host_capture_limit'):H.HostOccurrences().inspect(text,observation(text))

# Actual NativeScenario methods with fake observer/controller; no GUI launch.
import contextlib
S=load('ci-financial-scenario')
class CaptureFixture:
    deadline_ns=10**30
    def check(self):pass
    def preflight_input_budget(self):pass
class CaptureController:
    def __init__(self):self.captures=0;self.clicks=0
    def wait_render_progress(self):pass
    @contextlib.contextmanager
    def observe(self):self.captures+=1;yield object()
    def click(self,*args):self.clicks+=1
class CaptureOCR:
    def __init__(self):self.calls=0
    def read(self,*args):self.calls+=1;return PROMPT
class HostCaptureIntegration(unittest.TestCase):
    def make(self,mutate=lambda s:None):
        edge=CaptureController();ocr=CaptureOCR();generation=0
        def next_snapshot(deadline):
            nonlocal generation
            generation+=1;s=snapshot(observation(PROMPT));s['view_generation']=generation;mutate(s);return s
        return S.NativeScenario(edge,CaptureFixture(),next_snapshot),edge,ocr
    def test_one_real_capture_operation_bracketed_by_observer(self):
        scenario,edge,ocr=self.make();text,h=scenario.capture_host('Selecting',None,ocr)
        self.assertEqual((edge.captures,ocr.calls,edge.clicks),(1,1,0));self.assertEqual(text,PROMPT)
    def test_append_during_capture_rejects_before_input(self):
        def mutate(s):
            if s['view_generation']>=4:s['host_observation']['revision']=2
        scenario,edge,ocr=self.make(mutate)
        with self.assertRaises(S.C.Rejected):scenario.capture_host('Selecting',None,ocr)
        self.assertEqual((edge.captures,edge.clicks),(1,0))
    def test_editing_writing_no_capture(self):
        for entry in ('Editing','Writing'):
            def mutate(s):
                s['host_input']=True;h=s['host_observation'];h.update(entry=entry,view=None)
                if entry=='Editing':h['editor']=dict(ordinal=1,revision=1)
            scenario,edge,ocr=self.make(mutate)
            with self.assertRaises(S.C.Rejected):scenario.capture_host('Selecting',None,ocr)
            self.assertEqual((edge.captures,ocr.calls,edge.clicks),(0,0,0))
    def test_nonhost_stable_ignores_unrelated_host_append_only(self):
        def mutate(s):s['host_observation']['revision']=s['view_generation']
        scenario,edge,ocr=self.make(mutate);scenario.stable('Selecting',None)
        self.assertEqual(edge.clicks,0)
    def test_mismatched_editor_revision_zero_typing(self):
        def mutate(s):
            s['host_input']=True;h=s['host_observation'];h.update(entry='Editing',view=None,revision=2,editor=dict(ordinal=1,revision=2))
        scenario,edge,ocr=self.make(mutate)
        with self.assertRaises(S.C.Rejected):scenario.public_host_line('Selecting',None,'safe',(0,H.count(PROMPT),1))
        self.assertEqual(edge.clicks,0)

F=load('ci-financial-flow')
class PumpFixture:
    def preflight_input_budget(self):pass
    def reviewer_selection_path(self,owner):return '/ci-fixture/full-parent/f-test/coordinated-reviewer-selection-'+owner[-1]+'.json'
    _data={'delivery_choices':[]}
    def source(self,owner):return {'original_capture':{'scope':{'participant_id':owner}},'entry_selection':{'account_id':'synthetic'}}
class PumpTests(unittest.TestCase):
    def make(self):
        from unittest import mock
        f=F.FullFlow(mock.Mock(),PumpFixture(),mock.Mock(expected_profile=F.C.EXTERNAL_PROFILE),None)
        # These occurrence/visibility cases start after the genuine startup chain.
        f.startup_index=len(F.HOST_STARTUP)
        f.pending_host=f.pending_occurrence=f.host_prepared=f.host_deferred=f.host_ignored=None
        f.host_occurrences=F.H.HostOccurrences();f.host_visibility_steps=0;f.host_lines=0;f.host_coverage_context=None;f.host_coverage_steps=0
        f.host_rejection=None;f.host_stage='Unobserved';f.last_ocr=0;f.ocr_delay=0;f.last_capture=None
        f.reviewer_index=f.continue_index=f.result_index=0;f.challenges=set();f.host_paths=set()
        f.fixture=PumpFixture();f.ocr=None;f.retired=False;f.host_milestone=lambda _:f.retired
        f.captures=0;f.inputs=[];f.scroll_events=[];f.seeks=[]
        f.text=PROMPT;f.current=snapshot(observation(PROMPT));f.current['widgets'].append(dict(tag='BeginHostLine',owner=None,enabled=True,rect=[10,245,200,270]))
        class Native:
            @staticmethod
            def check_host_editor(s,o):S.NativeScenario.check_host_editor(s,o)
            def capture_host(self,*_):f.captures+=1;return f.text,f.current['host_observation']
            def stable(self,*_):return f.current
            def public_host_line(self,*args):f.inputs.append('typed')
        f.native=Native();f.snapshot=lambda:f.current
        f.press=lambda s,tag,owner,**kw:f.inputs.append(tag)
        f.seek=lambda s,tag,owner:f.seeks.append(tag) or False
        f.scroll=lambda s,body,owner,direction:f.scroll_events.append((body,direction)) or True
        return f
    def submit(self,f):
        h=f.current['host_observation'];h.update(entry='Editing',view=None,editor=dict(ordinal=f.host_lines,revision=h['revision']));f.current['host_input']=True
        original_widgets=f.current['widgets']
        f.current['widgets']=[dict(tag='ScrollRegion',owner=None,enabled=True,rect=[0,0,1280,800])]+[
            dict(tag=tag,owner=None,enabled=True,rect=[10,y,110,y+20])
            for tag,y in (('HostEditor',100),('HostSubmit',150))]
        f.pump_host(f.current)
        h.update(entry='Idle',editor=None);f.current['host_input']=False;f.current['widgets']=original_widgets
    def test_old_tail_wait_then_same_literal_new_occurrence(self):
        f=self.make();self.assertTrue(f.pump_host(f.current));self.submit(f)
        self.assertFalse(f.pump_host(f.current));self.assertEqual(f.captures,1)
        f.retired=True;f.current['host_observation']=observation(PROMPT,2,2*H.count(PROMPT));f.last_ocr=0
        self.assertTrue(f.pump_host(f.current));self.assertEqual(f.reviewer_index,2)
        self.assertEqual(f.inputs.count('BeginHostLine'),2);self.assertEqual(f.captures,2)
    def test_own_pre_tail_idle_protected_waits_for_actual_editor(self):
        f=self.make();f.pump_host(f.current);f.current['host_input']=True;f.current['host_observation']['view']=None
        self.assertTrue(f.pump_host(f.current));self.assertEqual(f.inputs,['BeginHostLine']);self.assertEqual(f.captures,1)
        self.submit(f);self.assertEqual(f.inputs,['BeginHostLine','typed','HostSubmit'])
    def test_wrong_editor_ordinal_types_nothing(self):
        f=self.make();f.pump_host(f.current);h=f.current['host_observation'];h.update(entry='Editing',view=None,editor=dict(ordinal=2,revision=1));f.current['host_input']=True
        with self.assertRaises(F.C.Rejected):f.pump_host(f.current)
        self.assertEqual(f.inputs,['BeginHostLine'])
    def test_source_review_not_stolen_by_consumed_or_unknown_context(self):
        f=self.make();f.pump_host(f.current);self.submit(f);f.current['widgets']=[]
        self.assertFalse(f.pump_host(f.current));self.assertEqual(f.scroll_events,[])
        f=self.make();f.text='ordinary output';f.current['host_observation']=observation(f.text)
        self.assertFalse(f.pump_host(f.current));f.current['widgets']=[];f.current['host_observation']['view']=None
        self.assertFalse(f.pump_host(f.current));self.assertEqual(f.captures,1);self.assertEqual(f.scroll_events,[])
    def test_new_deferred_prompt_reuses_identity_not_capture_or_viewport(self):
        f=self.make();f.reviewer_index=1
        self.assertFalse(f.pump_host(f.current));self.assertEqual(f.captures,1)
        f.current['widgets']=[];f.current['host_observation']['view']=None
        self.assertFalse(f.pump_host(f.current));self.assertEqual(f.captures,1);self.assertEqual(f.scroll_events,[])
        f.retired=True;self.assertTrue(f.pump_host(f.current));self.assertEqual(f.seeks,['BeginHostLine'])
        f.current['widgets']=[dict(tag='BeginHostLine',owner=None,enabled=True,rect=[10,10,100,30])]
        self.assertTrue(f.pump_host(f.current));self.assertEqual(f.inputs,['BeginHostLine']);self.assertEqual(f.captures,1)
    def test_larger_suffix_same_context_rechecks_previously_incomplete_prompt(self):
        f=self.make();f.text='actual originals: '
        f.current['host_observation']=observation(f.text,1,H.count(PROMPT))
        self.assertTrue(f.pump_host(f.current));self.assertEqual(f.captures,1)
        f.text=PROMPT;f.current['host_observation']=observation(PROMPT,1,H.count(PROMPT));f.last_ocr=0
        self.assertTrue(f.pump_host(f.current));self.assertEqual(f.captures,2)
        self.assertEqual(f.inputs,['BeginHostLine']);self.submit(f)
        self.assertFalse(f.pump_host(f.current));self.assertEqual(f.inputs.count('BeginHostLine'),1)
    def test_partial_startup_visibility_improves_only_after_actual_outer_wheel(self):
        f=self.make();f.text=PROMPT[-50:]
        f.current['host_observation']=observation(f.text,1,H.count(PROMPT))
        def wheel(s,body,owner,direction):
            f.scroll_events.append((body,direction))
            if body=='ScrollRegion':
                f.text=PROMPT;f.current['host_observation']=observation(PROMPT,1,H.count(PROMPT))
            return True
        f.scroll=wheel
        self.assertTrue(f.pump_host(f.current));self.assertEqual(f.scroll_events,[('ScrollRegion','up')])
        self.assertEqual(f.inputs,[]);f.last_ocr=0
        self.assertTrue(f.pump_host(f.current));self.assertEqual(f.inputs,['BeginHostLine'])
        self.assertEqual(f.captures,2)
    def test_tiny_last_row_requires_real_outer_wheel_before_reply(self):
        f=self.make();f.text=': ';f.current['host_observation']=observation(f.text,1,H.count(PROMPT))
        def wheel(s,body,owner,direction):
            f.scroll_events.append((body,direction))
            f.text=PROMPT;f.current['host_observation']=observation(PROMPT,1,H.count(PROMPT));return True
        f.scroll=wheel
        self.assertTrue(f.pump_host(f.current));self.assertEqual(f.inputs,[])
        self.assertEqual(f.scroll_events,[('ScrollRegion','up')]);f.last_ocr=0
        self.assertTrue(f.pump_host(f.current));self.assertEqual(f.inputs,['BeginHostLine'])
    def test_fully_visible_tiny_tail_is_not_navigation_authority(self):
        f=self.make();f.text=': ';f.current['host_observation']=observation(f.text)
        self.assertFalse(f.pump_host(f.current));self.assertFalse(f.pump_host(f.current))
        self.assertEqual(f.scroll_events,[]);self.assertEqual(f.inputs,[])
    def test_incidental_tail_navigation_yields_back_to_source_after_fixed_cap(self):
        f=self.make();f.text=': ';f.current['host_observation']=observation(f.text,1,100)
        for _ in range(16):self.assertTrue(f.pump_host(f.current))
        self.assertFalse(f.pump_host(f.current));self.assertFalse(f.pump_host(f.current))
        self.assertEqual(len(f.scroll_events),16);self.assertEqual(f.inputs,[]);self.assertEqual(f.captures,1)
    def test_larger_incomplete_coverage_cannot_renew_same_context_probe_budget(self):
        f=self.make();f.text=': ';f.current['host_observation']=observation(f.text,1,100)
        for _ in range(16):self.assertTrue(f.pump_host(f.current))
        self.assertFalse(f.pump_host(f.current))
        f.text='originals: ';f.current['host_observation']=observation(f.text,1,100);f.last_ocr=0
        self.assertFalse(f.pump_host(f.current));self.assertFalse(f.pump_host(f.current))
        self.assertEqual(len(f.scroll_events),16);self.assertEqual(f.captures,2);self.assertEqual(f.inputs,[])
    def test_outer_clipped_output_uses_both_real_scroll_targets(self):
        f=self.make();f.current['host_observation']['view']=None
        self.assertTrue(f.pump_host(f.current));self.assertTrue(f.pump_host(f.current))
        self.assertEqual(f.scroll_events,[('HostOutput','down'),('ScrollRegion','up')]);self.assertEqual(f.captures,0)
        f.current['host_observation']['view']=observation(PROMPT)['view'];self.assertTrue(f.pump_host(f.current));self.assertEqual(f.captures,1)
    def test_visibility_exhaustion_and_protection_are_finite(self):
        f=self.make();f.current['host_observation']['view']=None;f.host_visibility_steps=128
        with self.assertRaises(F.C.Rejected):f.pump_host(f.current)
        self.assertEqual(f.scroll_events,[])
        f=self.make();f.current['host_input']=True;f.current['host_observation'].update(entry='Writing',view=None)
        self.assertTrue(f.pump_host(f.current));self.assertEqual((f.captures,f.inputs,f.scroll_events),(0,[],[]))
        f.controller.wait_render_progress.assert_called_once_with()

import io
import json
class HostDiagnosticTests(unittest.TestCase):
    def test_fixed_category_shape_and_bounds(self):
        v=dict(version=1,category='tail_not_visible',startup_stage='Enrollment',attempted_lines=4)
        C.validate_host_diagnostic(v)
        for key,value in (('raw_text','forbidden'),('category','arbitrary'),('startup_stage','secret path'),('attempted_lines',129)):
            bad=dict(v);bad[key]=value
            with self.assertRaises(C.Rejected):C.validate_host_diagnostic(bad)
    def test_supervisor_holds_until_failure_and_rejects_success(self):
        supervisor=load('ci-financial-supervisor')
        v=dict(version=1,category='host_capture_count',startup_stage='Profile',attempted_lines=0)
        line=b'CI_FINANCIAL_HOST_DIAGNOSTIC '+json.dumps(v).encode()
        output=io.StringIO();records=supervisor.RuntimeRecords('external')
        with contextlib.redirect_stdout(output):records(line)
        self.assertEqual(output.getvalue(),'')
        result=supervisor.P.failure('snapshot')
        with contextlib.redirect_stdout(output):records(b'CI_FINANCIAL_RESULT '+json.dumps(result).encode())
        self.assertIn('HOST_DIAGNOSTIC',output.getvalue())
        records=supervisor.RuntimeRecords('external');records(line)
        candidate=dict(schema=1,profile=supervisor.P.C.EXTERNAL_PROFILE,native_oracle_verified=True,fixture_cleaned=True,display_cleaned=True,public_chain_verified=False,dispatch_attempted=False)
        with self.assertRaises(supervisor.Failure):records(b'CI_FINANCIAL_CANDIDATE '+json.dumps(candidate).encode())

if __name__=='__main__':unittest.main(verbosity=2)
