#!/usr/bin/env python3
"""Pure orchestration regressions; no build, Docker, fixture or qualification claim."""
import contextlib
import importlib.util
import io
import json
import pathlib
import tempfile
import unittest
from unittest.mock import patch

HERE=pathlib.Path(__file__).resolve().parent
spec=importlib.util.spec_from_file_location('financial_launch_under_test', HERE/'ci-financial-supervisor.py')
S=importlib.util.module_from_spec(spec);spec.loader.exec_module(S)

class LaunchTests(unittest.TestCase):
    def test_pinned_package_preflight(self):
        S.package_preflight()

    def test_exact_fresh_recipes(self):
        for name in S.FEATURES:
            args=S.build_recipe(name)
            self.assertEqual(args[:4],['rustup','run','1.99.0','cargo'])
            for flag in ('--locked','--release','--no-default-features','--message-format=json'):
                self.assertIn(flag,args)
            self.assertNotIn('--offline',args)
            self.assertNotIn('wholepact_delivery_ci',' '.join(args))
            if name=='pristine-setup':
                self.assertIn('--no-run',args);self.assertIn('--lib',args)
                self.assertEqual(args[args.index('--features')+1],
                                 'durable-proposal,synthetic-born-joined-qualification')
            else:
                self.assertEqual(args[4],'build')
                self.assertEqual(args[args.index('--features')+1],'coordinated-financial-runtime')
        self.assertEqual(S.build_recipe('coordinator-production'),S.build_recipe('coordinator-observed'))
        with self.assertRaises(S.Failure):S.build_recipe('historical-ui')

    def test_only_observed_receives_financial_cfgs(self):
        # Inspect actual orchestration with substituted compiler/image boundaries.
        with tempfile.TemporaryDirectory() as tmp:
            root=pathlib.Path(tmp);calls=[]
            def command(name,args,stage,env,**kwargs):
                calls.append((name,args,dict(env)))
                if '--list' in args:
                    return (S.LIVE_FIXTURE_TEST+': test\n\n1 test, 0 benchmarks\n').encode()
                return b''
            def artifact(raw,name,target):
                p=target/name;p.write_bytes(('executable-'+name).encode());return p
            def checked(args,stage,**kwargs):
                return (S.B.RUSTC+'\n').encode() if '--version' in args else b''
            with patch.object(S,'checked',side_effect=checked),patch.object(S,'exact_source'), \
                 patch.object(S,'encrypted_build_environment',side_effect=lambda root,env:env), \
                 patch.object(S,'build_command',side_effect=command),patch.object(S,'select_artifact',side_effect=artifact), \
                 contextlib.redirect_stdout(io.StringIO()):
                S.build_inputs(root,'a'*40)
            builds=[c for c in calls if '--message-format=json' in c[1]]
            self.assertEqual({n for n,_,_ in builds},set(S.FEATURES))
            for name,args,env in builds:
                self.assertEqual(env.get('RUSTFLAGS'),
                    '--cfg wholepact_financial_ci --cfg wholepact_financial_external_ci'
                    if name=='coordinator-observed' else None)
                self.assertTrue(set(env)<=S.BUILD_ENV_KEYS)
            self.assertEqual(len([c for c in calls if '--list' in c[1]]),1)

    def test_artifact_selector_rejects_wrong_features_and_duplicate(self):
        with tempfile.TemporaryDirectory() as tmp:
            target=pathlib.Path(tmp);exe=target/'coordinator';exe.write_bytes(b'ELF')
            row={'reason':'compiler-artifact','target':{'name':'wholepact-financial-coordinator','kind':['bin']},
                 'profile':{'test':False,'opt_level':'3','debug_assertions':False},
                 'features':S.FEATURES['coordinator-production'],'executable':str(exe)}
            raw=json.dumps(row).encode()
            self.assertEqual(S.select_artifact(raw,'coordinator-production',target),exe)
            with self.assertRaises(S.Failure):S.select_artifact(raw+b'\n'+raw,'coordinator-production',target)
            row['features']=['coordinated-witness-delivery-append']
            with self.assertRaises(S.Failure):S.select_artifact(json.dumps(row).encode(),'coordinator-production',target)

    def candidate(self,**changes):
        value=dict(schema=1,profile=S.P.C.EXTERNAL_PROFILE,native_oracle_verified=True,
                   fixture_cleaned=True,display_cleaned=True,public_chain_verified=False,dispatch_attempted=False)
        value.update(changes)
        return b'CI_FINANCIAL_CANDIDATE '+json.dumps(value).encode()

    def test_candidate_requires_exact_typed_no_dispatch_boundary(self):
        for change in ({'dispatch_attempted':True},{'public_chain_verified':True},
                       {'fixture_cleaned':False},{'native_oracle_verified':1},{'schema':True},
                       {'profile':'coordinated-financial-full-native-v1'}):
            with self.assertRaises(S.Failure):S.RuntimeRecords('external')(self.candidate(**change))
        records=S.RuntimeRecords('external');records(self.candidate())
        self.assertTrue(records.finish(0)['native_oracle_verified'])
        with self.assertRaises(S.Failure):records.finish(1)
        with self.assertRaises(S.Failure):records(self.candidate())

    def test_location_is_finite_once_and_failure_only(self):
        value={'phase':next(iter(S.P.C.PHASES)),'subphase':next(iter(S.P.C.SUBPHASES)),'owner':'Signer1'}
        line=b'CI_FINANCIAL_LOCATION '+json.dumps(value).encode()
        records=S.RuntimeRecords('external')
        with contextlib.redirect_stdout(io.StringIO()):records(line)
        with self.assertRaises(S.Failure):records(line)
        with self.assertRaises(S.Failure):records(self.candidate())
        value['private_text']='not publishable'
        with self.assertRaises(S.Failure):S.RuntimeRecords('external')(b'CI_FINANCIAL_LOCATION '+json.dumps(value).encode())

    def test_unknown_runtime_output_is_not_publishable(self):
        with self.assertRaises(S.Failure):S.RuntimeRecords('external')(b'private runtime text')
        with self.assertRaises(S.Failure):S.RuntimeRecords('external').finish(0)

    def test_inner_candidate_cannot_override_failed_container_cleanup(self):
        with patch.object(S,'names',return_value=[]),patch.object(S,'docker'), \
             patch.object(S,'inspect_isolation'),patch.object(S,'docker_env',return_value={}), \
             patch.object(S,'remove_container',side_effect=S.Failure('cleanup','container_remaining')), \
             contextlib.redirect_stdout(io.StringIO()):
            def command(args,stage,**kwargs):
                kwargs['on_line'](self.candidate());return 0,b''
            with patch.object(S,'command',side_effect=command):
                result,passed=S.run_case('external','sha256:'+'a'*64,'run','a'*40)
            self.assertTrue(result['native_oracle_verified']);self.assertFalse(passed)

    def test_runtime_image_must_extend_exact_fresh_foundation(self):
        foundation={'id':'foundation','layers':('layer1','layer2')}
        with patch.object(S,'image_descriptor',return_value=foundation):
            with patch.object(S,'build_image',return_value={'id':'runtime','layers':('layer1','layer2','layer3')}):
                self.assertEqual(S.final_image(None,'runtime','foundation','run','sha',foundation),'runtime')
            for wrong in ({'id':'foundation','layers':foundation['layers']},
                          {'id':'runtime','layers':('other','layer2','layer3')}):
                with patch.object(S,'build_image',return_value=wrong):
                    with self.assertRaises(S.Failure):S.final_image(None,'runtime','foundation','run','sha',foundation)

    def test_build_cache_cleanup_requires_explicit_zero(self):
        self.assertTrue(S.cache_empty(b'{"Type":"Build Cache","TotalCount":0,"Size":"0B"}'))
        for raw in (b'',b'{}',b'{"Type":"Build Cache","TotalCount":1,"Size":"0B"}',
                    b'{"Type":"Build Cache","TotalCount":0,"Size":"1MB"}'):
            self.assertFalse(S.cache_empty(raw))

    def test_workflow_is_distinct_and_always_cleans(self):
        workflow=(HERE.parent/'.github/workflows/durable-native-linux.yml').read_text()
        self.assertIn('"$mode" == financial-ui',workflow)
        self.assertIn("steps.mode.outputs.gate != 'financial-ui'",workflow)
        self.assertIn("always() && steps.mode.outputs.gate == 'financial-ui'",workflow)
        self.assertEqual(workflow.count('run: bash scripts/ci-financial-linux.sh'),1)
        self.assertEqual(workflow.count('run: bash scripts/ci-ui-linux.sh'),1)

if __name__=='__main__':unittest.main()
