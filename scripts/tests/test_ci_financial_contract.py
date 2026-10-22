import importlib.util
import pathlib
import sys
import unittest

ROOT=pathlib.Path(__file__).resolve().parents[1]
def load(name):
    key=name.replace('-','_');spec=importlib.util.spec_from_file_location(key,ROOT/(name+'.py'))
    obj=importlib.util.module_from_spec(spec);sys.modules[key]=obj;spec.loader.exec_module(obj);return obj
C=load('ci-financial-contract');O=load('ci-financial-output');S=load('ci-financial-scenario')

class ContractTests(unittest.TestCase):
    def test_closed_roles_are_seventeen_actors_sixteen_children(self):
        self.assertEqual(len(C.ROLES),17);self.assertEqual(len(C.PARENTS),16)
        self.assertEqual(len(C.WITNESSES),13)
    def test_profile_does_not_widen_old_controller(self):
        old=load('ci-ui-controller');new=load('ci-financial-controller')
        self.assertEqual(old.SESSION_NS,120_000_000_000)
        self.assertEqual(new.SESSION_NS,1_800_000_000_000)
        self.assertNotEqual(old.MAGIC,new.MAGIC);self.assertNotEqual(old.APP_ID,new.APP_ID)
        self.assertEqual(new.MAX_PROGRESS,8192)
    def test_duplicate_keys_and_nonfinite_rejected(self):
        for raw in ('{"x":1,"x":2}','{"x":NaN}','{"x":Infinity}'):
            with self.assertRaises(Exception):C.loads(raw)
    def test_actual_phase_names_not_success_alias(self):
        self.assertIn('NormalClosing',C.PHASES);self.assertNotIn('NormalFinished',C.PHASES)
        self.assertIn('SelectNextV3',C.ACTIONS)
    def test_no_stub_success(self):
        with self.assertRaises(Exception):O.validate_completed([],100,0)
        with self.assertRaises(Exception):O.public_result(None,exact_build_verified=True,container_removed=True)
    def test_failure_never_claims_public_or_native_pass(self):
        f=O.failure('password-content-must-not-leak')
        self.assertEqual(f['code'],'contract');self.assertFalse(f['synthetic_full_native_verified'])
        self.assertFalse(f['public_chain_verified'])
    def test_actual_ocr_challenge_only(self):
        text='Type APPROVE 0123456789abcdef to approve this exact operation, or anything else to reject: '
        self.assertEqual(S.actual_approval_line(text),'APPROVE 0123456789abcdef')
        for wrong in (text+text,text.replace('APPROVE','APPR0VE'),text.replace('abcdef','abcdeg'),'APPROVE 0123456789abcdef'):
            with self.assertRaises(Exception):S.actual_approval_line(wrong)
    def test_secret_constructor_is_closed_and_repr_redacted(self):
        with self.assertRaises(Exception):S.F.SyntheticSecret(object(),b'not synthetic')
        secret=S.F.SyntheticSecret(S.F._TOKEN,b'synthetic-recovery-review-password')
        self.assertEqual(repr(secret),'<SyntheticSecret redacted>')
        self.assertEqual(secret.consume(lambda v:len(v)),34)
        self.assertTrue(all(b==0 for b in secret._bytes))
        with self.assertRaises(Exception):secret.consume(lambda v:None)
    def test_snapshot_has_no_arbitrary_text(self):
        snap={'phase':'Selecting','subphase':'None','owner':None,'view_generation':1,
              'focused':True,'secret_input':False,'host_input':False,'pixels_per_point':1,
              'viewport':[1280,800],'widgets':[], 'host_observation':dict(revision=0,nonws_end=0,context_valid=True,entry='Idle',editor=None,view=None)}
        C.validate_snapshot(snap)
        snap['host_text']='must never enter records'
        with self.assertRaises(Exception):C.validate_snapshot(snap)
    def test_unknown_and_offscreen_widgets_rejected(self):
        base={'phase':'Selecting','subphase':'None','owner':None,'view_generation':1,
              'focused':True,'secret_input':False,'host_input':False,'pixels_per_point':1,
              'viewport':[1280,800],'widgets':[], 'host_observation':dict(revision=0,nonws_end=0,context_valid=True,entry='Idle',editor=None,view=None)}
        for tag,rect in [('OverrideAuthority',[0,0,10,10]),('BeginHostLine',[0,0,1281,10])]:
            base['widgets']=[{'tag':tag,'owner':None,'enabled':True,'rect':rect}]
            with self.assertRaises(Exception):C.validate_snapshot(base)

if __name__=='__main__':unittest.main()
