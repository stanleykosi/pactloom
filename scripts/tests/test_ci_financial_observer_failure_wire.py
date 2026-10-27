"""Pure first-observation failure wire tests; no product, container or network."""
import contextlib
import copy
import importlib.util
import io
import json
import pathlib
import sys
import unittest
from unittest import mock

ROOT=pathlib.Path(__file__).resolve().parents[1]
spec=importlib.util.spec_from_file_location('observer_failure_container_tested',ROOT/'ci-financial-container.py')
M=importlib.util.module_from_spec(spec);sys.modules[spec.name]=M;spec.loader.exec_module(M)
S=M.load('ci-financial-supervisor')
MARKER='CI_FINANCIAL_OBSERVER_FAILURE_DIAGNOSTIC '


def unavailable():
    return dict(availability='Unavailable',read_index=None,since_first_successful_read_ns=None,events=[])


def diagnostic(observed=False):
    first=unavailable()
    if observed:
        first=dict(availability='Observed',read_index=4,since_first_successful_read_ns=29,
            events=[dict(role='Signer2',kind='Failure',sequence=17,actor_elapsed_ns=23,
                         facts=dict(code='transport'))])
    return dict(version=1,site='NextSnapshotFailureRecords',first_observed=first)


def line(value):return (MARKER+json.dumps(value,separators=(',',':'))).encode()


def candidate(profile):
    return b'CI_FINANCIAL_CANDIDATE '+json.dumps(dict(schema=1,profile=profile,
        native_oracle_verified=True,fixture_cleaned=True,display_cleaned=True,
        public_chain_verified=False,dispatch_attempted=False)).encode()


def result(code='observer_failure',profile=None):
    return b'CI_FINANCIAL_RESULT '+json.dumps(S.P.failure(code,profile or M.C.SEMANTIC_PROFILE)).encode()


class ObserverFailureWire(unittest.TestCase):
    def runtime(self,profile=None):return S.RuntimeRecords('external',profile or M.C.SEMANTIC_PROFILE)
    def flow(self,value):
        flow=mock.Mock();flow.observer.first_failure_observation.return_value=copy.deepcopy(value['first_observed'])
        return flow
    def error(self,site='NextSnapshotFailureRecords'):
        error=M.C.Rejected('observer_failure');error.observer_failure_site=site;return error
    def test_container_emits_exact_cached_batch_without_fresh_observation(self):
        value=diagnostic(True);flow=self.flow(value);out=io.StringIO()
        with contextlib.redirect_stdout(out),mock.patch.object(M.time,'monotonic_ns',side_effect=AssertionError('clock')):
            M.emit_cached_observer_failure(flow,self.error())
        self.assertEqual(out.getvalue(),line(value).decode()+'\n')
        flow.observer.first_failure_observation.assert_called_once_with()
        flow.observer.read.assert_not_called();flow.observer.next_snapshot.assert_not_called()
    def test_container_unavailable_still_preserves_exception_site(self):
        out=io.StringIO()
        with contextlib.redirect_stdout(out):M.emit_cached_observer_failure(None,self.error('ReadIo'))
        self.assertEqual(json.loads(out.getvalue()[len(MARKER):]),dict(version=1,site='ReadIo',first_observed=unavailable()))
    def test_container_missing_site_is_unclassified(self):
        out=io.StringIO()
        with contextlib.redirect_stdout(out):M.emit_cached_observer_failure(None,M.C.Rejected('observer_failure'))
        self.assertEqual(json.loads(out.getvalue()[len(MARKER):])['site'],'Unclassified')
    def test_container_unrelated_failure_neither_reads_nor_emits(self):
        flow=self.flow(diagnostic(True));out=io.StringIO()
        with contextlib.redirect_stdout(out):M.emit_cached_observer_failure(flow,M.C.Rejected('deadline'))
        self.assertEqual(out.getvalue(),'');flow.observer.first_failure_observation.assert_not_called()
    def test_container_rejects_invalid_site_without_raw_exception_output(self):
        error=self.error('/private/path token');out=io.StringIO()
        with contextlib.redirect_stdout(out):M.emit_cached_observer_failure(None,error)
        self.assertEqual(out.getvalue(),'');self.assertEqual(error.code,'observer_failure')
    def test_container_cache_failure_is_best_effort(self):
        flow=self.flow(diagnostic());flow.observer.first_failure_observation.side_effect=RuntimeError('private')
        error=self.error();out=io.StringIO()
        with contextlib.redirect_stdout(out):M.emit_cached_observer_failure(flow,error)
        self.assertEqual(out.getvalue(),'');self.assertEqual(error.code,'observer_failure')
    def test_container_output_failure_is_best_effort(self):
        error=self.error()
        with mock.patch('builtins.print',side_effect=BrokenPipeError('private')):
            M.emit_cached_observer_failure(None,error)
        self.assertEqual(error.code,'observer_failure')
    def test_supervisor_holds_until_associated_failure_then_forwards_once(self):
        for profile in (M.C.EXTERNAL_PROFILE,M.C.SEMANTIC_PROFILE):
            with self.subTest(profile=profile):
                runtime=self.runtime(profile);out=io.StringIO();value=diagnostic(True)
                with contextlib.redirect_stdout(out):runtime(line(value))
                self.assertEqual(out.getvalue(),'')
                with contextlib.redirect_stdout(out):runtime(result(profile=profile))
                self.assertEqual(runtime.finish(1)['code'],'observer_failure')
                rows=out.getvalue().splitlines()
                self.assertEqual(len(rows),2)
                self.assertTrue(rows[0].startswith(MARKER));self.assertTrue(rows[1].startswith('CI_FINANCIAL_FAILURE '))
                self.assertEqual(json.loads(rows[0][len(MARKER):]),value)
    def test_supervisor_rejects_duplicate(self):
        runtime=self.runtime();runtime(line(diagnostic()))
        with self.assertRaises(S.Failure):runtime(line(diagnostic()))
    def test_supervisor_rejects_success_with_diagnostic(self):
        runtime=self.runtime();runtime(line(diagnostic()))
        with self.assertRaises(S.Failure):runtime(candidate(M.C.SEMANTIC_PROFILE))
        self.assertIsNone(runtime.result)
    def test_supervisor_unchanged_success_without_diagnostic(self):
        runtime=self.runtime();runtime(candidate(M.C.SEMANTIC_PROFILE))
        self.assertTrue(runtime.finish(0)['native_oracle_verified'])
    def test_supervisor_rejects_different_failure_before_emission(self):
        for code in ('deadline','process','snapshot','input_disabled'):
            with self.subTest(code=code):
                runtime=self.runtime();runtime(line(diagnostic()));out=io.StringIO()
                with contextlib.redirect_stdout(out),self.assertRaises(S.Failure):runtime(result(code))
                self.assertEqual(out.getvalue(),'');self.assertIsNone(runtime.result)
    def test_supervisor_existing_observer_failure_needs_no_diagnostic(self):
        runtime=self.runtime()
        with contextlib.redirect_stdout(io.StringIO()):runtime(result())
        self.assertEqual(runtime.finish(1)['code'],'observer_failure')
    def test_supervisor_rejects_forged_fields_and_facts(self):
        values=[]
        value=diagnostic();value['raw']='private';values.append(value)
        value=diagnostic(True);value['first_observed']['events'][0]['facts']['code']='private';values.append(value)
        value=diagnostic(True);value['first_observed']['events'].append(copy.deepcopy(value['first_observed']['events'][0]));values.append(value)
        value=diagnostic(True);value['first_observed']['read_index']=True;values.append(value)
        value=diagnostic(True);value['first_observed']['since_first_successful_read_ns']=M.C.ORIGINAL_NS+1;values.append(value)
        for value in values:
            with self.subTest(value=value):
                runtime=self.runtime();out=io.StringIO()
                with contextlib.redirect_stdout(out),self.assertRaises(S.Failure):runtime(line(value))
                self.assertEqual(out.getvalue(),'');self.assertIsNone(runtime.observer_failure_diagnostic)
    def test_supervisor_diagnostic_emit_failure_preserves_original_result(self):
        runtime=self.runtime();runtime(line(diagnostic()));emitted=[]
        def emit(kind,value):
            emitted.append(kind)
            if kind=='OBSERVER_FAILURE_DIAGNOSTIC':raise BrokenPipeError('private')
        with mock.patch.object(S,'emit',side_effect=emit):runtime(result())
        self.assertEqual(emitted,['OBSERVER_FAILURE_DIAGNOSTIC','FAILURE'])
        self.assertEqual(runtime.finish(1)['code'],'observer_failure')
    def test_supervisor_original_line_bound_and_terminal_guard_remain(self):
        with self.assertRaises(S.Failure):self.runtime()(b' ' * 8193)
        runtime=self.runtime()
        with contextlib.redirect_stdout(io.StringIO()):runtime(result())
        with self.assertRaises(S.Failure):runtime(line(diagnostic()))


if __name__=='__main__':unittest.main()
