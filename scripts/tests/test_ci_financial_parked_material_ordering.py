"""Python-only portability, exact-source and failed-run custody checks."""
import contextlib
import hashlib
import importlib.util
import io
import json
import pathlib
import re
import tempfile
import types
import unittest
from unittest import mock

ROOT=pathlib.Path(__file__).resolve().parents[2]
SPEC=importlib.util.spec_from_file_location('parked_material_trace_tested',ROOT/'scripts/ci-financial-parked-material-ordering-trace.py')
G=importlib.util.module_from_spec(SPEC);SPEC.loader.exec_module(G)

class ParkedMaterialOrderingTests(unittest.TestCase):
    def test_exact_nine_file_inverse_without_external_baseline(self):
        old,new,before,after=G.extract(ROOT)
        self.assertEqual({p:G.sha(v) for p,v in old.items()},G.PINS)
        self.assertEqual({p:G.sha(v) for p,v in new.items()},G.CANDIDATE_PINS)
        self.assertEqual(new[G.MATERIAL].replace(after,before,1),old[G.MATERIAL])
        self.assertEqual(new[G.DIAG].replace(', RelayPump, RelayFinish, ParkedMaterialBounds});',', RelayPump, RelayFinish});',1),old[G.DIAG])
        self.assertEqual(set(p for p in old if old[p]!=new[p]),{G.MATERIAL,G.DIAG})
        self.assertEqual(after.count('self.bounds.check()'),1)
        self.assertEqual(after.count('::native('),1)
        self.assertEqual(G.DEFAULT_SOURCE,ROOT)
        self.assertNotIn('/workspace/',pathlib.Path(G.__file__).read_text())

    def test_generation_is_subprocess_free_and_exact_reviewed_rust_and_46_pieces(self):
        with tempfile.TemporaryDirectory() as tmp,mock.patch.object(G.subprocess,'Popen',side_effect=AssertionError('native invocation forbidden')):
            out=pathlib.Path(tmp)/'out';binding=G.generate(ROOT,out)
            self.assertEqual({p.name for p in out.iterdir()},{'parked-material-ordering.rs','binding.json'})
            self.assertEqual(binding,json.loads((out/'binding.json').read_bytes()))
            self.assertFalse(binding['executed']);self.assertTrue(binding['whole_file_inverses'])
            self.assertEqual(G.sha((out/'parked-material-ordering.rs').read_bytes()),'fe22fe83ca9309bad499590e2a90076f2206c0f0f146afd4c6d5d90e7c1a2cad')
            self.assertEqual(len(binding['pieces']),46)
            self.assertEqual(G.sha(json.dumps(binding['pieces'],sort_keys=True,separators=(',',':'))),'83a4ee11174b135ba4d13c67a895cf72bc5488d1e0c550bfe79ef779dbbb33b9')
            self.assertEqual(binding['baseline_sha256'],G.PINS)
            self.assertEqual(binding['candidate_sha256'],G.CANDIDATE_PINS)

    def test_exact_eight_cases_no_ignored_and_literal_owning_drop_relay_boundaries(self):
        names=re.findall(r'#\[test\]fn ([a-z0-9_]+)',G.TESTS)
        self.assertEqual(len(names),8);self.assertEqual(len(set(names)),8);self.assertEqual(set(names),G.TEST_NAMES)
        self.assertNotIn('#[ignore',G.TESTS)
        for token in ('Barrier::new(2)','std::thread::spawn','relay.pump().unwrap_err()','let before_relay=financial_ci_host_diagnostics::sample_failure();'):
            self.assertIn(token,G.PREFIX)
        self.assertIn('LifecycleCheck',G.TESTS);self.assertNotIn('NormalObservation',G.TESTS)
        with tempfile.TemporaryDirectory() as tmp,mock.patch.object(G,'TEST_NAMES',G.TEST_NAMES|{'unreviewed'}):
            with self.assertRaises(AssertionError):G.generate(ROOT,pathlib.Path(tmp)/'out')
            self.assertFalse((pathlib.Path(tmp)/'out').exists())

    def test_raw_byte_crlf_unrelated_and_missing_sources_are_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            source=pathlib.Path(tmp)
            for path in G.PINS:
                target=source/path;target.parent.mkdir(parents=True,exist_ok=True);target.write_bytes((ROOT/path).read_bytes())
            for path in G.PINS:
                target=source/path;original=target.read_bytes()
                for changed in (original+b'\n',original.replace(b'\n',b'\r\n')):
                    with self.subTest(path=path,kind='CRLF' if b'\r\n' in changed else 'suffix'):
                        target.write_bytes(changed)
                        with self.assertRaises(AssertionError):G.extract(source)
                target.unlink()
                with self.assertRaises(FileNotFoundError):G.extract(source)
                target.write_bytes(original)

    def test_exact_once_partial_duplicate_and_unrelated_inverses_fail_closed(self):
        with tempfile.TemporaryDirectory() as tmp:
            source=pathlib.Path(tmp)
            for path in G.PINS:
                target=source/path;target.parent.mkdir(parents=True,exist_ok=True);target.write_bytes((ROOT/path).read_bytes())
            original=(source/G.MATERIAL).read_text()
            for changed in (original.replace(G.AFTER,G.BEFORE,1),original+'\n'+G.AFTER,original.replace('let result = self.bounds.check();','let result = Ok(());',1),original+'\n'):
                (source/G.MATERIAL).write_text(changed)
                pins={**G.CANDIDATE_PINS,G.MATERIAL:G.sha(changed)}
                with self.subTest(sha=G.sha(changed)),mock.patch.object(G,'CANDIDATE_PINS',pins):
                    with self.assertRaises(AssertionError):G.extract(source)
            (source/G.MATERIAL).write_text(original)
            original=(source/G.DIAG).read_text()
            for changed in (original.replace(', ParkedMaterialBounds','',1),original+original,original+'\n'):
                (source/G.DIAG).write_text(changed)
                with self.subTest(sha=G.sha(changed)),mock.patch.object(G,'CANDIDATE_PINS',{**G.CANDIDATE_PINS,G.DIAG:G.sha(changed)}):
                    with self.assertRaises(AssertionError):G.extract(source)

    def test_duplicate_missing_and_unclosed_method_extraction_rejected(self):
        for source in ('fn x(){0}\nfn x(){1}','fn y(){0}','fn x(){'):
            with self.subTest(source=source),self.assertRaises(AssertionError):G.block(source,'fn x()')

    def test_fresh_output_refuses_overwrite_and_preserves_prior_receipt(self):
        with tempfile.TemporaryDirectory() as tmp:
            out=pathlib.Path(tmp)/'out';out.mkdir();prior=out/'binding.json';prior.write_bytes(b'prior custody')
            with mock.patch.object(G.subprocess,'Popen',side_effect=AssertionError('native invocation forbidden')):
                with self.assertRaises(FileExistsError):G.generate(ROOT,out)
            self.assertEqual(prior.read_bytes(),b'prior custody');self.assertEqual(len(list(out.iterdir())),1)

    def _mock_main(self,root,*,fault=None,version=None,host=None,listing=None,missing=False):
        out=root/'out';compiler=root/'rustc';compiler.write_bytes(b'inert compiler file; never executed')
        def checked(command,path,timeout):
            if command[-1]=='--version':kind='version';text=(version or G.RUSTC_VERSION)+'\n'
            elif command[-1]=='-Vv':kind='verbose';text=G.RUSTC_VERSION+'\nhost: '+(host or G.RUSTC_HOST)+'\n'
            elif '--test' in command:kind='compile';text='inert compile log\n';pathlib.Path(command[command.index('-o')+1]).write_bytes(b'inert test binary; never executed')
            elif command[-1]=='--list':kind='list';text=listing if listing is not None else ''.join(name+': test\n' for name in sorted(G.TEST_NAMES))
            else:kind='tests';text='test result: ok. 8 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out\n'
            path.write_text(text)
            if fault and kind==fault[0]:raise G.CommandFailure(fault[1],7 if fault[1]=='nonzero' else -9)
            return text
        args=['trace','--source',str(ROOT),'--out',str(out),'--run','--rustc',str(compiler)]
        caught=None
        with mock.patch.object(G.sys,'argv',args),mock.patch.object(G.shutil,'which',return_value=None if missing else str(compiler)),mock.patch.object(G,'checked',side_effect=checked),mock.patch.object(G.subprocess,'Popen',side_effect=AssertionError('native invocation forbidden')),contextlib.redirect_stdout(io.StringIO()):
            try:G.main()
            except BaseException as error:caught=error
        return caught,json.loads((out/'execution/receipt.json').read_bytes()),out

    def test_mocked_wrong_missing_compiler_and_wrong_host_stop_before_compile(self):
        for kwargs,expected_count in [({'version':'wrong compiler'},1),({'missing':True},0),({'host':'wrong-host'},2)]:
            with self.subTest(kwargs=kwargs),tempfile.TemporaryDirectory() as tmp:
                error,r,out=self._mock_main(pathlib.Path(tmp),**kwargs)
                self.assertIsNotNone(error);self.assertEqual(r['status'],'failed')
                self.assertFalse(r['native_execution_attempted']);self.assertEqual(r['compiled_profiles'],[])
                self.assertEqual(len(r['commands']),expected_count)
                if not kwargs.get('missing'):self.assertEqual(r['invoked_executable']['sha256'],G.sha(b'inert compiler file; never executed'))

    def test_mocked_compile_list_test_failures_preserve_partial_attempt_receipts(self):
        for kind,reason,attempted,listed,started in [('compile','nonzero',False,[],[]),('list','timed_out',True,[],[]),('tests','output_limit',True,['production'],['production']),('tests','nonzero',True,['production'],['production'])]:
            with self.subTest(kind=kind,reason=reason),tempfile.TemporaryDirectory() as tmp:
                error,r,out=self._mock_main(pathlib.Path(tmp),fault=(kind,reason))
                self.assertIsInstance(error,G.CommandFailure);self.assertEqual(r['status'],reason)
                self.assertEqual(r['native_execution_attempted'],attempted)
                self.assertEqual(r['native_listings_completed'],listed);self.assertEqual(r['tests_started'],started)
                self.assertEqual(r['profiles_passed'],[]);self.assertEqual(r['commands'][-1]['status'],reason)
                self.assertTrue((out/'execution'/r['commands'][-1]['log']).read_bytes())
                self.assertIn(r['commands'][-1]['log'],r['logs'])

    def test_mocked_mismatched_or_duplicate_listing_never_starts_tests(self):
        for listing in ['unreviewed: test\n',''.join(name+': test\n' for name in sorted(G.TEST_NAMES))+sorted(G.TEST_NAMES)[0]+': test\n']:
            with self.subTest(listing=listing),tempfile.TemporaryDirectory() as tmp:
                error,r,_=self._mock_main(pathlib.Path(tmp),listing=listing)
                self.assertIsInstance(error,AssertionError);self.assertEqual(r['status'],'failed')
                self.assertTrue(r['native_execution_attempted']);self.assertEqual(r['native_listings_completed'],['production'])
                self.assertEqual(r['tests_started'],[]);self.assertEqual(r['profiles_passed'],[])

    def test_mocked_success_requires_both_exact_profiles_and_post_source_custody(self):
        with tempfile.TemporaryDirectory() as tmp:
            error,r,_=self._mock_main(pathlib.Path(tmp))
            self.assertIsNone(error);self.assertEqual(r['status'],'success')
            for key in ('compiled_profiles','native_listings_completed','tests_started','profiles_passed'):
                self.assertEqual(r[key],['production','semantic'])
            self.assertTrue(r['source_pins_after']);self.assertEqual(len(r['commands']),8)
            self.assertEqual([c['timeout_seconds'] for c in r['commands']],[15,15,60,10,30,60,10,30])
            compile_commands=[c['argv'] for c in r['commands'] if c['kind']=='compile']
            self.assertNotIn('--cfg',compile_commands[0]);self.assertIn('wholepact_financial_rendered_host_semantic_ci',compile_commands[1])
            self.assertEqual(set(r['binary_sha256']),{'production','semantic'})

    def test_bounded_reader_retains_nonzero_timeout_overflow_and_spawn_error(self):
        class FakeSelector:
            def __init__(self):self.mapping={}
            def register(self,file,event):self.mapping[7]=types.SimpleNamespace(fd=7,fileobj=file)
            def get_map(self):return self.mapping
            def select(self,_):return [(key,None) for key in self.mapping.values()]
            def unregister(self,_):self.mapping.clear()
            def close(self):pass
        for label,data,times,status,expected in [('nonzero',[b'partial',b''],[0]*10,7,b'partial'),('timed_out',[b'partial'],[0,0,2,2],-9,b'partial'),('output_limit',[b'123456'],[0]*10,-9,b'1234')]:
            with self.subTest(label=label),tempfile.TemporaryDirectory() as tmp:
                path=pathlib.Path(tmp)/'command.log';proc=mock.Mock();proc.stdout=mock.Mock();proc.wait.return_value=status;proc.poll.return_value=status
                with mock.patch.object(G.subprocess,'Popen',return_value=proc),mock.patch.object(G.selectors,'DefaultSelector',FakeSelector),mock.patch.object(G.os,'read',side_effect=data),mock.patch.object(G.time,'monotonic',side_effect=times),mock.patch.object(G,'MAX_LOG_BYTES',4 if label=='output_limit' else 32),contextlib.redirect_stderr(io.StringIO()):
                    with self.assertRaises(G.CommandFailure) as raised:G.checked(['inert'],path,1)
                self.assertEqual(raised.exception.reason,label);self.assertEqual(path.read_bytes(),expected)
                if label!='nonzero':proc.kill.assert_called()
        with tempfile.TemporaryDirectory() as tmp,mock.patch.object(G.subprocess,'Popen',side_effect=FileNotFoundError('absent executable')):
            path=pathlib.Path(tmp)/'command.log'
            with self.assertRaises(FileNotFoundError):G.checked(['inert'],path,1)
            self.assertEqual(path.read_bytes(),b'absent executable\n')

    def test_preflight_mandatory_exact_call_after_compiler_and_all_p90_gates_inverse(self):
        workflow=(ROOT/'.github/workflows/deadline-preflight.yml').read_bytes().decode('utf-8')
        command="          print(run(rustup+['python3', '-I', '-B', 'scripts/ci-financial-parked-material-ordering-trace.py', '--source', str(repo), '--out', str(root/'parked-material-ordering-traces'), '--run'], env=env, timeout=180))\n"
        prior="          print(run(rustup+['python3', '-I', '-B', 'scripts/ci-financial-retired-wall-trace.py', '--source', str(repo), '--out', str(root/'retired-wall-traces'), '--run'], env=env, timeout=180))\n"
        self.assertEqual(workflow.count(command),1);self.assertEqual(workflow.count('scripts/ci-financial-parked-material-ordering-trace.py'),1)
        self.assertIn(prior+command,workflow)
        self.assertLess(workflow.index(command),workflow.index('scripts/ci-financial-admit-read-trace.py'))
        self.assertLess(workflow.index("print(profile+': compiler and API fences passed')"),workflow.index(command))
        self.assertEqual(workflow.count('retained-signing-check-preflight-p92'),4)
        added="              'financial_ci_actor_diagnostics::tests::signed_result_minimum_masks_keep_atomic_detail_and_legacy_shape',\n              'financial_ci_actor_diagnostics::tests::signed_result_driver_rejects_invalid_bits_masks_roles_and_pids',\n              'financial_ci_actor_diagnostics::tests::signed_result_driver_first_wins_never_mixes_owner_class_or_mask',\n              'financial_ci_actor_diagnostics::tests::signed_result_stage_inventory_preserves_all_original_discriminants',\n"
        current='          assert len(semantic_names) == 17 and len(set(semantic_names)) == 17\n'
        historical='          assert len(semantic_names) == 13 and len(set(semantic_names)) == 13\n'
        self.assertEqual(workflow.count(added),1);self.assertEqual(workflow.count(current),1)
        workflow=workflow.replace(added,'',1).replace(current,historical,1)
        restored=workflow.replace(command,'',1).replace('name: Retained signing check preflight only\n','name: Retained signing wall preflight only\n',1).replace('retained-signing-check-preflight-p92','retained-signing-wall-preflight-p90')
        self.assertEqual(G.sha(restored),'2296a3379ab8562a26cb82904009e6cd76cd568f4b1e5e14921ab9daad57f408')

if __name__=='__main__':unittest.main()
