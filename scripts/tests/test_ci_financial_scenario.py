"""Fake native edges only: these tests do not qualify UI presentation."""
import importlib.util
import pathlib
import sys
import unittest
ROOT=pathlib.Path(__file__).resolve().parents[1]
spec=importlib.util.spec_from_file_location('financial_scenario_tested',ROOT/'ci-financial-scenario.py')
S=importlib.util.module_from_spec(spec);sys.modules[spec.name]=S;spec.loader.exec_module(S)

class Fixture:
    deadline_ns=123
    def check(self):pass
    def preflight_input_budget(self):return 0
class Controller:
    def __init__(self):self.calls=[]
    def wait_render_progress(self):self.calls.append(('progress',))
    def click(self,*point):self.calls.append(('click',*point))
    def observe(self):raise AssertionError('capture should not be reached')

def snapshot(generation,*,protected=False,enabled=True,rect=None):
    return dict(phase='Selecting',subphase='None',owner=None,view_generation=generation,
                focused=True,secret_input=protected,host_input=False,pixels_per_point=1,
                host_observation=dict(revision=0,nonws_end=0,context_valid=True,entry='Idle',editor=None,view=None),
                viewport=[1280,800],widgets=[dict(tag='BeginHostLine',owner=None,
                rect=rect or [10,10,30,30],enabled=enabled)])

class ScenarioTests(unittest.TestCase):
    def setup_scenario(self,snapshots):
        edge=Controller();iterator=iter(snapshots)
        return S.NativeScenario(edge,Fixture(),lambda deadline:next(iterator)),edge
    def test_one_native_click_then_no_retry(self):
        scenario,edge=self.setup_scenario([snapshot(1),snapshot(2)])
        scenario.click('Selecting',None,'BeginHostLine')
        self.assertEqual(edge.calls,[('progress',),('click',20,20),('progress',)])
        with self.assertRaises(Exception):scenario.click('Selecting',None,'BeginHostLine')
        self.assertEqual(len(edge.calls),3)
    def test_changed_geometry_cannot_click(self):
        scenario,edge=self.setup_scenario([snapshot(1),snapshot(2,rect=[10,10,40,40])])
        with self.assertRaises(Exception):scenario.click('Selecting',None,'BeginHostLine')
        self.assertFalse(any(call[0]=='click' for call in edge.calls))
    def test_disabled_control_never_clicked(self):
        scenario,edge=self.setup_scenario([snapshot(1,enabled=False),snapshot(2,enabled=False)])
        with self.assertRaises(Exception):scenario.click('Selecting',None,'BeginHostLine')
        self.assertFalse(any(call[0]=='click' for call in edge.calls))
    def test_protected_editor_never_captured(self):
        scenario,edge=self.setup_scenario([snapshot(1,protected=True),snapshot(2,protected=True)])
        with self.assertRaises(Exception):scenario.capture_host('Selecting',None,None)
        self.assertFalse(any(call[0]=='click' for call in edge.calls))
    def test_generation_replay_rejected(self):
        scenario,edge=self.setup_scenario([snapshot(1),snapshot(1)])
        with self.assertRaises(Exception):scenario.click('Selecting',None,'BeginHostLine')
    def test_phase_mismatch_rejected(self):
        scenario,edge=self.setup_scenario([snapshot(1),snapshot(2)])
        with self.assertRaises(Exception):scenario.click('SignCommitted',None,'BeginHostLine')

if __name__=='__main__':unittest.main()
