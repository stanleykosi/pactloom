"""Python-only exact-source/test-custody checks; never compile or run Rust."""
import contextlib
import hashlib
import io
import importlib.util
import json
import pathlib
import re
import sys
import tempfile
import types
import unittest
from unittest import mock

ROOT=pathlib.Path(__file__).resolve().parents[2]
SPEC=importlib.util.spec_from_file_location('retired_wall_trace_tested',ROOT/'scripts/ci-financial-retired-wall-trace.py')
G=importlib.util.module_from_spec(SPEC);sys.modules[SPEC.name]=G;SPEC.loader.exec_module(G)

class RetiredWallSourceTests(unittest.TestCase):
    def test_exact_actual_full_file_inverse_and_unchanged_helper(self):
        value=G.extract(ROOT)
        self.assertEqual(G.digest(value['candidate_source']),G.CANDIDATE_SHA256)
        self.assertEqual(G.digest(value['current_before']),G.P91_CUSTODY_SHA256)
        self.assertEqual(G.digest(value['legacy_source']),'c60162e32fd54f848afffbb2ff09707989349dc1ea22932a8d51c7e6ab06a45d')
        restored=value['candidate_source']
        for item in reversed(G.P92_RESTORATION):
            if item['path']==G.CUSTODY:
                self.assertEqual(restored.count(item['after']),1)
                restored=restored.replace(item['after'],item['before'],1)
        self.assertEqual(restored,value['current_before'])
        self.assertEqual(restored.replace(G.AFTER,G.BEFORE,1),value['legacy_source'])
        self.assertEqual(G.digest((ROOT/G.STATE).read_bytes().decode('utf-8')),'33c4b1f180f6f4093fd195a65a27921bceea06cde078b9917e22f3a3048b0079')
        self.assertEqual(G.digest(value['helper']),'54199d6a5f727eaba9154ebabfb3491dd04e0de9e463d0936a783d948a788349')
    def test_same_immutable_four_bounds_and_original_guard_suffix(self):
        value=G.extract(ROOT);new=value['before_check'];old=value['legacy_check']
        restored=G.unwrap_check_macros(G.unwrap_check_macros(value['kernel'],'signed_result_check_at'),'signed_result_denied_at')
        restored=restored.replace('    fn check_impl(&self,#[cfg(wholepact_financial_rendered_host_semantic_ci)] mut capture:Option<&mut Option<SignedResultCheckFailure>>)->Result<()>','    pub(super) fn check(&self)->Result<()>',1)
        self.assertEqual(restored,new)
        self.assertIn('self.check_impl(None)',value['candidate_check'])
        self.assertNotIn('driver_detail',value['candidate_check'])
        self.assertNotIn('mark_failed',value['candidate_source'])
        self.assertEqual(value['observed'].count('self.check_impl(Some(&mut detail))'),1)
        order=('let original=self.service.min(self.writer).min(self.writer_wall).min(self.entry.original_source);',
               'crate::channel::require_time(original)?;','self.entry.retirement_clock_bounds()?;',
               'state::observe_shared_wall(&self.last_wall,original,state::wall_ms)?',
               'if wall<self.service_valid_from_ms||wall>=self.service_valid_until_ms',
               'if self.core.phase.revoked()','if !self.core.phase.quiescent(){self.core.check()?;}',
               'if self.core.phase.revoked(){return Err(rejected("retired signed custody revoked"));}')
        positions=[new.index(token) for token in order];self.assertEqual(positions,sorted(positions))
        self.assertEqual(new.split('        if self.core.phase.revoked()',1)[1],old.split('        if self.core.phase.revoked()',1)[1])
        self.assertNotIn('fetch_max',new);self.assertNotIn('Instant::now',new)
        self.assertEqual(new.count('observe_shared_wall('),1)
    def test_generation_is_source_only_with_exact_literal_bodies_and_receipts(self):
        value=G.extract(ROOT)
        with tempfile.TemporaryDirectory() as tmp,mock.patch.object(G.subprocess,'run',side_effect=AssertionError('native invocation forbidden')):
            out=pathlib.Path(tmp)/'out';binding=G.generate(ROOT,out)
            self.assertEqual({p.name for p in out.iterdir()},{'retired-wall-trace.rs','binding.json'})
            self.assertEqual(binding,json.loads((out/'binding.json').read_text()))
            self.assertTrue(binding['generated']);self.assertFalse(binding['executed'])
            rust=(out/'retired-wall-trace.rs').read_text()
            self.assertEqual(hashlib.sha256(rust.encode()).hexdigest(),binding['rust_sha256'])
            self.assertEqual(rust.count(value['candidate_check']),1)
            self.assertEqual(rust.count(value['kernel']),1)
            self.assertEqual(rust.count(value['observed']),1)
            self.assertEqual(rust.count(value['dispatch']),1)
            self.assertIn('pub(super) fn check_candidate(&self)->Result<()>{self.check()}',rust)
            self.assertEqual(rust.count(value['legacy_check'].replace('fn check(','fn check_legacy(',1)),1)
            self.assertEqual(rust.count(value['helper']),1);self.assertEqual(rust.count(value['actor_macro']),1)
            self.assertEqual(binding['files'],{G.CUSTODY:G.CANDIDATE_SHA256,G.STATE:G.STATE_SHA256,G.SIGNING:G.SIGNING_SHA256,G.ACTOR:G.ACTOR_SHA256,G.UI:G.UI_SHA256})
            self.assertEqual(binding['test_count'],27);self.assertEqual(binding['legacy_test_count'],17);self.assertEqual(binding['new_test_count'],10)
            self.assertTrue(binding['production_kernel_macro_inverse'])
    def test_authored_native_inventory_covers_race_and_original_negatives_without_ignored(self):
        names=re.findall(r'#\[test\]\s*fn\s+([A-Za-z0-9_]+)',G.TESTS)
        self.assertEqual(len(names),17);self.assertEqual(set(names),G.LEGACY_EXPECTED_TESTS)
        self.assertEqual(len(set(names)),len(names));self.assertNotIn('#[ignore',G.TESTS)
        for token in ('Arc::ptr_eq(&record,&a_record)','Barrier::new(2)','a_sampled.wait();a_published.wait()',
                      'std::thread::spawn','(count,high),(1,101)','(count,high),(2,101)',
                      'Arc::ptr_eq(&token,&payload.0)','CoreFault::Host','CoreFault::Root',
                      'for which in 0..4','clock(7)','record.retired_index=32'):
            self.assertIn(token,G.TESTS)
    def test_unrelated_partial_duplicate_and_guard_mutations_fail_closed(self):
        originals={path:(ROOT/path).read_bytes() for path in (G.CUSTODY,G.STATE,G.SIGNING,G.ACTOR,G.UI)}
        with tempfile.TemporaryDirectory() as tmp:
            source=pathlib.Path(tmp)
            for path,data in originals.items():
                p=source/path;p.parent.mkdir(parents=True,exist_ok=True);p.write_bytes(data)
            for path,data in originals.items():
                for bad in (data+b'\n',data.replace(b'\n',b'\r\n'),data[:-1]):
                    with self.subTest(path=path,changed=hashlib.sha256(bad).hexdigest()):
                        (source/path).write_bytes(bad)
                        with self.assertRaises(AssertionError):G.extract(source)
                (source/path).write_bytes(data)
            original=originals[G.CUSTODY].decode()
            cases=[('stale original',G.extract(ROOT)['current_before']),('partial inverse',original.replace('let original=self.service.min(self.writer).min(self.writer_wall).min(self.entry.original_source);','let original=self.service;',1))]
            for needle,replacement in [('capture,EntryBounds,self.entry.retirement_clock_bounds()','capture,EntryBounds,Ok(())'),('&self.last_wall,original,state::wall_ms','&self.last_wall,self.service,state::wall_ms'),('wall>=self.service_valid_until_ms','false'),('self.retired_index>=32','false'),('self.core.phase.signing_phase(self.entry.slot())!=6','false'),('if !self.core.phase.quiescent()','if true'),('self.check_impl(None)','self.check_impl(Some(&mut None))')]:
                self.assertIn(needle,original);cases.append((needle,original.replace(needle,replacement,1)))
            for name,bad in cases:
                with self.subTest(case=name):
                    (source/G.CUSTODY).write_text(bad)
                    with self.assertRaises(AssertionError):G.extract(source)
            (source/G.CUSTODY).write_text(original)
            # Even a repinned whole source may not bypass the strict P92 inverse.
            bad=original+'\n'
            (source/G.CUSTODY).write_text(bad)
            with mock.patch.object(G,'CANDIDATE_SHA256',G.digest(bad)),self.assertRaises(AssertionError):G.extract(source)

    def test_new_actual_boundary_inventory_and_mask_owner_scope_are_explicit(self):
        names=re.findall(r'#\[test\]\s*fn\s+([A-Za-z0-9_]+)',G.P92_TESTS)
        self.assertEqual(len(names),7);self.assertEqual(set(names)|G.LEGACY_EXPECTED_TESTS|G.UI_EXPECTED_TESTS,G.EXPECTED_TESTS)
        for token in ('for mask in 1..=15','for owner in 0..2','check_before_p92','check_for_restriction','RetiredIndex','retired_roots','observe_active(&r.core,1)','sample_failure().is_none()','test_foreign_latch','Arc::ptr_eq(&token,&payload.0)'):
            self.assertIn(token,G.P92_TESTS)
        self.assertNotIn('#[ignore',G.P92_TESTS)
    def test_fatal_ui_actual_methods_delegates_and_strict_whole_source_inverse(self):
        value=G.extract(ROOT)
        self.assertEqual(G.digest(value['prior_ui']),G.UI_BASELINE_SHA256)
        self.assertEqual(value['fatal_delegate'],'    pub(crate) fn check_current_for_fatal_observation(&self)->Result<()>{self.record.check_for_restriction()}')
        self.assertIn('self.current_with_signed_check(|s| s.check_current())',value['ui_parts']['current'])
        self.assertIn('self.current_with_signed_check(|s| signed_result_fatal_check!(s))',value['ui_parts']['fatal'])
        self.assertEqual(value['ui_parts']['kernel'].count('check(s)'),1)
        self.assertEqual(value['ui_parts']['kernel'].count('.check_current()'),2)
        self.assertEqual(value['ui_parts']['macro'].count('check_signed_result_for_fatal_restriction($custody)'),1)
        self.assertEqual(value['ui_parts']['macro'].count('($custody).check_current()'),1)
        self.assertEqual(len(re.findall(r'#\[test\]\s*fn\s+([A-Za-z0-9_]+)',G.UI_TESTS)),3)
        with tempfile.TemporaryDirectory() as tmp:
            out=pathlib.Path(tmp)/'out';binding=G.generate(ROOT,out);rust=(out/'retired-wall-trace.rs').read_text()
            self.assertEqual(binding['ui_test_count'],3)
            self.assertTrue(rust.startswith('#![allow(dead_code)]\nextern crate self as wholepact_financial_coordinator_origin;'))
            for piece in list(value['ui_parts'].values())+[value['fatal_delegate']]:self.assertEqual(rust.count(piece),1)
            self.assertIn('custody.check_current_for_fatal_observation()',rust)
            self.assertIn('no whole Window/revoke runtime simulation',binding['limits'])
        for token in ('for owner in 0..2','for case in 0..12','Some(which!=1)','Some(which!=2)','return_read','return_exact','sample_failure().is_none()','Arc::ptr_eq(&token,&payload.0)'):
            self.assertIn(token,G.UI_TESTS)

    def test_duplicate_missing_and_unclosed_extractions_are_rejected(self):
        for source,needle in [('fn x(){0}\nfn x(){1}','fn x()'),('fn y(){0}','fn x()'),('fn x(){','fn x()')]:
            with self.subTest(source=source),self.assertRaises(AssertionError):G.block(source,needle)
    def test_generation_rejects_changed_authored_test_selection(self):
        with tempfile.TemporaryDirectory() as tmp,mock.patch.object(G,'EXPECTED_TESTS',G.EXPECTED_TESTS|{'unreviewed_extra'}),mock.patch.object(G.subprocess,'run',side_effect=AssertionError('native invocation forbidden')):
            with self.assertRaises(AssertionError):G.generate(ROOT,pathlib.Path(tmp)/'out')
            self.assertFalse((pathlib.Path(tmp)/'out').exists())

    def test_mocked_runner_preserves_nonzero_timeout_and_missing_compiler_evidence(self):
        with tempfile.TemporaryDirectory() as tmp:
            out=pathlib.Path(tmp)/'test.log'
            cases=[(types.SimpleNamespace(stdout='nonzero output',returncode=7),None,SystemExit,'nonzero output'),
                   (None,G.subprocess.TimeoutExpired(['rustc'],1,output=b'partial timeout'),G.subprocess.TimeoutExpired,'partial timeout'),
                   (None,FileNotFoundError('absent compiler'),FileNotFoundError,'absent compiler\n')]
            for result,error,kind,expected in cases:
                with self.subTest(kind=kind.__name__),mock.patch.object(G.subprocess,'run',return_value=result,side_effect=error) as run,contextlib.redirect_stderr(io.StringIO()):
                    with self.assertRaises(kind):G.run(['rustc'],out,1)
                    self.assertEqual(out.read_text(),expected);run.assert_called_once()
    def test_mocked_wrong_compiler_stops_before_any_compile(self):
        with tempfile.TemporaryDirectory() as tmp:
            out=pathlib.Path(tmp)/'out'
            args=['retired-wall-trace','--source',str(ROOT),'--out',str(out),'--run']
            with mock.patch.object(G.sys,'argv',args),mock.patch.object(G.subprocess,'run',return_value=types.SimpleNamespace(stdout='wrong rustc\n',returncode=0)) as run,contextlib.redirect_stdout(io.StringIO()):
                with self.assertRaisesRegex(RuntimeError,'wrong rustc identity'):G.main()
            self.assertEqual(run.call_count,1);self.assertEqual(run.call_args.args[0],['rustc','--version'])
            receipt=json.loads((out/'execution/receipt.json').read_text())
            self.assertEqual(receipt['status'],'failed');self.assertFalse(receipt['native_execution_attempted'])
            self.assertEqual(receipt['profiles_passed'],[])
            self.assertEqual(receipt['log_sha256']['compiler-version.log'],hashlib.sha256(b'wrong rustc\n').hexdigest())
    def test_mocked_incomplete_native_inventory_never_starts_tests(self):
        with tempfile.TemporaryDirectory() as tmp:
            out=pathlib.Path(tmp)/'out';commands=[]
            def process(command,**kwargs):
                commands.append(command)
                text=G.PINNED_RUSTC+'\n' if command==['rustc','--version'] else 'unreviewed: test\n' if command[-1]=='--list' else ''
                return types.SimpleNamespace(stdout=text,returncode=0)
            args=['retired-wall-trace','--source',str(ROOT),'--out',str(out),'--run']
            with mock.patch.object(G.sys,'argv',args),mock.patch.object(G.subprocess,'run',side_effect=process),contextlib.redirect_stdout(io.StringIO()):
                with self.assertRaisesRegex(AssertionError,'compiled test inventory mismatch'):G.main()
            self.assertEqual(len(commands),3);self.assertFalse(any('--test-threads=1' in command for command in commands))
            receipt=json.loads((out/'execution/receipt.json').read_text())
            self.assertEqual(receipt['status'],'failed');self.assertTrue(receipt['native_execution_attempted']);self.assertEqual(receipt['native_listings_completed'],['production']);self.assertEqual(receipt['compiled_profiles'],['production']);self.assertEqual(receipt['tests_started'],[]);self.assertEqual(receipt['profiles_passed'],[])

    def test_preflight_runs_exact_retired_wall_trace_after_compiler_and_preserves_all_p89_gates(self):
        workflow=(ROOT/'.github/workflows/deadline-preflight.yml').read_bytes().decode('utf-8')
        # P93 changes only this exact preflight identity; restore all prior owning checks.
        import hashlib
        self.assertEqual(hashlib.sha256(workflow.encode()).hexdigest(),'51965fa1d26a81490a8cbb1fccb9498f7aedf1b98c2bf378dc8c070e192be686')
        self.assertEqual(workflow.count('name: Durable result lifecycle preflight only\n'),1)
        self.assertEqual(workflow.count('durable-result-lifecycle-preflight-p93'),4)
        workflow=workflow.replace('name: Durable result lifecycle preflight only\n','name: Retained signing check preflight only\n',1).replace('durable-result-lifecycle-preflight-p93','retained-signing-check-preflight-p92')
        self.assertEqual(hashlib.sha256(workflow.encode()).hexdigest(),'962ebf0b81831706896cc3ad46f882afed1e532966abb06a23322d2174ac48ff')
        additions = ''.join("              'financial_ci_actor_diagnostics::tests::"+name+"',\n" for name in (
            'signed_result_minimum_masks_keep_atomic_detail_and_legacy_shape',
            'signed_result_driver_rejects_invalid_bits_masks_roles_and_pids',
            'signed_result_driver_first_wins_never_mixes_owner_class_or_mask',
            'signed_result_stage_inventory_preserves_all_original_discriminants'))
        self.assertEqual(workflow.count(additions),1)
        selected="          assert len(semantic_names) == 17 and len(set(semantic_names)) == 17\n"
        historical="          assert len(semantic_names) == 13 and len(set(semantic_names)) == 13\n"
        self.assertEqual(workflow.count(selected),1)
        workflow=workflow.replace(additions,'',1).replace(selected,historical,1)
        self.assertEqual(workflow.count('retained-signing-check-preflight-p92'),4)
        self.assertEqual(workflow.count('name: Retained signing check preflight only\n'),1)
        workflow=workflow.replace('name: Retained signing check preflight only\n','name: Parked material review preflight only\n',1).replace('retained-signing-check-preflight-p92','parked-material-review-preflight-p91')
        p91_command="          print(run(rustup+['python3', '-I', '-B', 'scripts/ci-financial-parked-material-ordering-trace.py', '--source', str(repo), '--out', str(root/'parked-material-ordering-traces'), '--run'], env=env, timeout=180))\n"
        self.assertEqual(workflow.count(p91_command),1)
        self.assertEqual(workflow.count('parked-material-review-preflight-p91'),4)
        self.assertEqual(workflow.count('name: Parked material review preflight only\n'),1)
        workflow=workflow.replace(p91_command,'',1).replace('name: Parked material review preflight only\n','name: Retained signing wall preflight only\n',1).replace('parked-material-review-preflight-p91','retained-signing-wall-preflight-p90')
        command="          print(run(rustup+['python3', '-I', '-B', 'scripts/ci-financial-retired-wall-trace.py', '--source', str(repo), '--out', str(root/'retired-wall-traces'), '--run'], env=env, timeout=180))\n"
        self.assertEqual(workflow.count(command),1)
        self.assertEqual(workflow.count('scripts/ci-financial-retired-wall-trace.py'),1)
        self.assertEqual(workflow.count('retained-signing-wall-preflight-p90'),4)
        self.assertNotIn('endpoint-restriction-preflight-p89',workflow)
        self.assertEqual(workflow.count('name: Retained signing wall preflight only\n'),1)
        self.assertIn("for profile in ['minimal', 'production', 'observed-pixel', 'observed-semantic']:",workflow)
        self.assertLess(workflow.index("print(profile+': compiler and API fences passed')"),workflow.index(command))
        self.assertLess(workflow.index('scripts/ci-financial-service-lifetime-trace.py'),workflow.index(command))
        self.assertLess(workflow.index(command),workflow.index('      - name: Exact historical P40 adapter'))
        restored=workflow.replace(command,'',1).replace('name: Retained signing wall preflight only\n','name: Endpoint restriction return preflight only\n',1).replace('retained-signing-wall-preflight-p90','endpoint-restriction-preflight-p89')
        self.assertEqual(hashlib.sha256(restored.encode()).hexdigest(),'f8136db52df79ff5a0587170755b421dca87b2d9f13fa752a374a610b914f675')

if __name__=='__main__':unittest.main()
