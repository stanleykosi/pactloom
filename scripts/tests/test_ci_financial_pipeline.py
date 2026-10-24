"""Focused same-job handoff/cleanup and closed timing regressions; no native run."""
import contextlib
import hashlib
import importlib.util
import os
import pathlib
import tempfile
import unittest
from unittest.mock import patch

HERE=pathlib.Path(__file__).resolve().parents[1]
spec=importlib.util.spec_from_file_location('pipeline_supervisor',HERE/'ci-financial-supervisor.py')
S=importlib.util.module_from_spec(spec);spec.loader.exec_module(S)
IDENTITY=dict(repository='stanleykosi/pactloom',source='a'*40,source_tree='b'*40,run_id=123,attempt=1)
CLOSURE={path:'c'*64 for path in S.A.BUILD_SCRIPTS}


class PipelineTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup)
        self.root=pathlib.Path(self.tmp.name)

    def test_markers_are_closed_monotonic_and_do_not_replace_failures(self):
        for name in ('build','image','fixture-runtime'):
            rows=[]
            with patch.object(S,'emit',side_effect=lambda k,v:rows.append((k,v))),patch.object(S.time,'monotonic_ns',side_effect=[1_000_000,2_000_000,8_000_000]):
                with S.PipelineStage(name) as stage:stage.passed=True
            self.assertEqual([r[1]['status'] for r in rows],['running','passed'])
            self.assertEqual([r[1]['elapsed_ms'] for r in rows],[1,7])
            self.assertTrue(all(r[0]=='STAGE' and r[1]['fullflow'] is False for r in rows))
        with self.assertRaises(S.Failure):S.PipelineStage('runtime supplied text')
        interrupted=S.Failure('supervisor','interrupted')
        with patch.object(S,'emit',side_effect=interrupted):
            with self.assertRaises(S.Failure) as caught:
                with S.PipelineStage('build'):pass
        self.assertIs(caught.exception,interrupted)
        for error in (S.Failure('compile','command_failed'),S.Failure('supervisor','interrupted'),RuntimeError('private runtime text')):
            with patch.object(S,'emit',side_effect=OSError('unavailable')):
                with self.assertRaises(type(error)) as caught:
                    with S.PipelineStage('build'):raise error
            self.assertIs(caught.exception,error)
        rows=[]
        with patch.object(S,'emit',side_effect=lambda k,v:rows.append(v)):
            with S.PipelineStage('fixture-runtime'):pass
        self.assertEqual(rows[-1]['status'],'failed')

    def main_context(self,mode,*,cleanup=True):
        stack=contextlib.ExitStack();self.addCleanup(stack.close)
        stack.enter_context(patch.dict(os.environ,{'RUNNER_TEMP':str(self.root),'GITHUB_OUTPUT':str(self.root/'outputs')}))
        stack.enter_context(patch.object(S.sys,'argv',['supervisor',mode]))
        stack.enter_context(patch.object(S,'context',return_value=('a'*40,'owned')))
        stack.enter_context(patch.object(S,'exact_source'))
        stack.enter_context(patch.object(S,'emit'))
        stack.enter_context(patch.object(S,'cleanup',return_value=cleanup))
        runtime=stack.enter_context(patch.object(S,'run_case',side_effect=AssertionError('must not run')))
        return stack,runtime

    def test_build_ready_is_after_cleanup_and_no_runtime_claim(self):
        stack,runtime=self.main_context('build')
        stack.enter_context(patch.object(S,'build_inputs',return_value=dict(sha256='d'*64,size=10240)))
        def publish(pin):
            self.assertEqual(list(self.root.glob('wholepact-financial-*')),[])
            S.cleanup.assert_called_once()
        published=stack.enter_context(patch.object(S,'publish_compiled_bundle',side_effect=publish))
        self.assertEqual(S.main(),0);published.assert_called_once();runtime.assert_not_called()
        kinds=[call.args[0] for call in S.emit.call_args_list]
        self.assertIn('BUILD_RESULT',kinds);self.assertNotIn('RESULT',kinds)

    def test_failed_build_cleanup_or_handoff_never_publishes_or_runs(self):
        for mode,where in [('build','build'),('build','cleanup'),('build','cleanup-exception'),('run-built','handoff')]:
            with self.subTest(mode=mode,where=where),contextlib.ExitStack() as scoped:
                stack,runtime=self.main_context(mode)
                # Close this scenario's patches before the next scenario.
                scoped.callback(stack.close)
                stack.enter_context(patch.object(S,'build_inputs',side_effect=S.Failure('compile','command_failed') if where=='build' else None,return_value=dict(sha256='d'*64,size=10240)))
                if where=='cleanup':S.cleanup.return_value=False
                if where=='cleanup-exception':S.cleanup.side_effect=RuntimeError('cleanup unavailable')
                stack.enter_context(patch.object(S,'same_job_inputs',side_effect=S.Failure('compile','artifact_bundle')))
                published=stack.enter_context(patch.object(S,'publish_compiled_bundle'))
                self.assertEqual(S.main(),1);published.assert_not_called();runtime.assert_not_called()
                self.assertEqual(list(self.root.glob('wholepact-financial-*')),[])

    def test_run_built_orders_verified_handoff_image_runtime_and_cleanup(self):
        for failure in (None,'image','runtime'):
            with self.subTest(failure=failure),contextlib.ExitStack() as scoped:
                stack,runtime=self.main_context('run-built');scoped.callback(stack.close)
                events=[]
                def boundary(name,value):
                    def call(*args,**kwargs):
                        events.append(name)
                        if name==failure:raise S.Failure(name,'command_failed')
                        return value
                    return call
                build=stack.enter_context(patch.object(S,'build_inputs',side_effect=AssertionError('must not recompile')))
                stack.enter_context(patch.object(S,'same_job_inputs',side_effect=boundary('verified',self.root/'inputs')))
                stack.enter_context(patch.object(S,'package_preflight'))
                stack.enter_context(patch.object(S,'stage_image_context',side_effect=boundary('context',self.root/'context')))
                stack.enter_context(patch.object(S,'docker',side_effect=boundary('pull',b'')))
                stack.enter_context(patch.object(S,'build_image',side_effect=boundary('foundation',{})))
                stack.enter_context(patch.object(S,'final_image',side_effect=boundary('image','sha256:'+'d'*64)))
                runtime.side_effect=boundary('runtime',({},True))
                S.cleanup.side_effect=boundary('cleanup',True)
                self.assertEqual(S.main(),0 if failure is None else 1)
                build.assert_not_called()
                self.assertEqual(events,['verified','context','pull','foundation','image']+([] if failure=='image' else ['runtime'])+['cleanup'])
                self.assertEqual(runtime.call_count,0 if failure=='image' else 1)
                self.assertEqual(list(self.root.glob('wholepact-financial-*')),[])

    def bundle(self):
        directory=self.root/'wholepact-financial-build-123-1';directory.mkdir(mode=0o700)
        artifacts=self.root/'producer-artifacts';artifacts.mkdir()
        for name in S.A.NAMES:(artifacts/name).write_bytes(b'\x7fELF'+name.encode())
        bundle=directory/'build.tar'
        S.A.export_bundle(artifacts,bundle,IDENTITY,CLOSURE,S.I.profile())
        env={'RUNNER_TEMP':str(self.root),'GITHUB_RUN_ID':'123','GITHUB_RUN_ATTEMPT':'1',
             'FINANCIAL_BUILD_SHA256':hashlib.sha256(bundle.read_bytes()).hexdigest(),
             'FINANCIAL_BUILD_SIZE':str(bundle.stat().st_size)}
        return bundle,env

    def test_current_bundle_is_staged_independently_and_changed_identity_is_denied(self):
        bundle,env=self.bundle()
        with patch.dict(os.environ,env),patch.object(S,'compiled_source_identity',return_value=(IDENTITY,CLOSURE)),patch.object(S,'exact_source'),patch.object(S,'emit'):
            target=self.root/'runtime';target.mkdir()
            inputs=S.same_job_inputs(target,'a'*40)
            self.assertEqual({p.name for p in inputs.iterdir()},set(S.A.NAMES))
            self.assertTrue(all(p.stat().st_nlink==1 and p.stat().st_ino!=(self.root/'producer-artifacts'/p.name).stat().st_ino for p in inputs.iterdir()))
        cases=[(dict(IDENTITY,**{key:value}),CLOSURE) for key,value in [('source','e'*40),('source_tree','f'*40),('run_id',124),('attempt',2)]]
        cases.append((IDENTITY,{**CLOSURE,S.A.BUILD_SCRIPTS[0]:'d'*64}))
        for index,identity in enumerate(cases):
            with self.subTest(identity=identity),patch.dict(os.environ,env),patch.object(S,'compiled_source_identity',return_value=identity),patch.object(S,'exact_source'):
                target=self.root/f'denied-{index}';target.mkdir()
                with self.assertRaises(S.Failure):S.same_job_inputs(target,'a'*40)
                self.assertFalse((target/'artifacts').exists())

    def test_handoff_rejects_bad_output_corruption_and_linked_bundle(self):
        bundle,env=self.bundle()
        mutations=[{'FINANCIAL_BUILD_SHA256':''},{'FINANCIAL_BUILD_SIZE':'-1'},{'FINANCIAL_BUILD_SHA256':'0'*64},{'FINANCIAL_BUILD_SIZE':'1'}]
        for index,changes in enumerate(mutations):
            with self.subTest(changes=changes),patch.dict(os.environ,{**env,**changes}),patch.object(S,'compiled_source_identity',return_value=(IDENTITY,CLOSURE)):
                target=self.root/f'bad-{index}';target.mkdir()
                with self.assertRaises(S.Failure):S.same_job_inputs(target,'a'*40)
        backup=self.root/'original.tar';bundle.rename(backup);bundle.symlink_to(backup)
        with patch.dict(os.environ,env),patch.object(S,'compiled_source_identity',return_value=(IDENTITY,CLOSURE)):
            with self.assertRaises(S.Failure):S.same_job_inputs(self.root,'a'*40)

    def test_workflow_success_requires_build_and_runtime_and_always_cleanup(self):
        text=(HERE.parent/'.github/workflows/durable-native-linux.yml').read_text()
        build=text.index('id: financial_build');upload=text.index('name: Preserve exact credential-free compiled financial bundle');runtime=text.index('id: financial\n',build)
        self.assertLess(build,upload);self.assertLess(upload,runtime)
        self.assertIn('steps.financial_build.outcome == \'success\'',text[upload:runtime])
        self.assertIn('FINANCIAL_BUILD_SHA256: ${{ steps.financial_build.outputs.artifact_bundle_sha256 }}',text)
        self.assertIn('FINANCIAL_BUILD_SIZE: ${{ steps.financial_build.outputs.artifact_bundle_size }}',text)
        self.assertIn('test "$FINANCIAL_BUILD_READY" = true',text)
        self.assertIn('steps.financial.outcome == \'success\'',text[runtime:])
        self.assertIn('timeout-minutes: 210',text)
        for name in ('Financial recipe and projection gates (no build or fixture)',
                     'Fresh exact-source financial build (no runtime fixture)',
                     'Financial image and native runtime (verified same-job fresh bundle)'):
            block=text.split('- name: '+name,1)[1].split('- name:',1)[0]
            self.assertIn('timeout-minutes: 200',block)
        for name in ('Verify financial containers, temporary images and build cache removed','Remove exact same-job credential-free financial bundle'):
            block=text.split('- name: '+name,1)[1].split('- name:',1)[0]
            self.assertIn('if: always()',block)


if __name__=='__main__':unittest.main()
