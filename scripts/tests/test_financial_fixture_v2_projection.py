#!/usr/bin/env python3
"""Pure closed-schema tests; no payment, socket or native authority execution."""
import copy
import importlib.util
import json
import pathlib
import unittest
import contextlib
import io
import os
import sys
import tempfile

SPEC = importlib.util.spec_from_file_location('financial_projection', pathlib.Path(__file__).parents[1] / 'ci-durable-financial-output.py')
M = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(M)


def timing(reader=False):
    completed = [1] * (15 if reader else 26)
    return dict(budget_ms=1800000, elapsed_before_first_window_ms=0 if reader else 1,
                completed_window_elapsed_ms=completed, current_window_elapsed_ms=1,
                total_elapsed_ms=len(completed)+(1 if reader else 2), clamped=False)


def row():
    value = dict.fromkeys(M.FIELDS)
    value.update({key: True for key in M.PROOFS})
    value.update(schema=5, fixture_profile='durable_financial_1800_v2', result='passed',
                 root_cleanup='closed_absent', completed_extraction_checkpoint_count=1,
                 dedicated_dispatch_admissions=2, synthetic_backend_only=True,
                 public_chain_verified=False, source_diagnostic_withheld=False,
                 producer_timing=timing(), reader_timing=timing(True))
    return value


def failed(reader=True):
    value = row()
    value.update(result='failed', first_failure='CompletedReopen' if reader else 'FinalTransactionRetention', boundary_outcome='unverified')
    windows = M.READER_PROGRESS_WINDOWS if reader else M.PROGRESS_WINDOWS
    index = len(windows)-1
    value['progress_failure'] = dict(reason='PhaseDeadline', last=dict(window=index, owner=windows[index][0], phase=windows[index][1], call='Shutdown', last_native=None))
    value['progress_timing'] = copy.deepcopy(value['reader_timing' if reader else 'producer_timing'])
    return value


class Projection(unittest.TestCase):
    def refused(self, value):
        with self.assertRaises((ValueError, TypeError, KeyError)):
            M.validate(value)

    def test_success_keeps_separate_timings(self):
        M.validate(row())

    def test_producer_and_reader_failure_keep_own_timings(self):
        for reader in (False, True):
            M.validate(failed(reader))

    def test_exact_profile_and_version(self):
        for key, bad in [('schema',4),('schema',True),('fixture_profile','legacy900'),('fixture_profile',None)]:
            v=row();v[key]=bad;self.refused(v)

    def test_each_cleanup_gate(self):
        for key in ('producer_reaped','producer_group_absent','reader_reaped','reader_group_absent','root_cleanup'):
            v=row();v[key]='unverified' if key=='root_cleanup' else False;self.refused(v)

    def test_producer_timing_without_reader_cleanup_is_allowed_on_producer_failure(self):
        v=failed(False);v.update(reader_timing=None,reader_reaped=False,reader_group_absent=False);M.validate(v)

    def test_timing_budget_and_type_bounds(self):
        for key,bad in [('budget_ms',900000),('budget_ms',1800001),('budget_ms',True),('total_elapsed_ms',1800001),('total_elapsed_ms',True),('clamped',1),('clamped',True)]:
            v=row();v['producer_timing'][key]=bad;self.refused(v)

    def test_role_window_lengths(self):
        for field, maximum in [('producer_timing',26),('reader_timing',15)]:
            v=row();t=v[field];t['completed_window_elapsed_ms']=[0]*(maximum+1);t['total_elapsed_ms']=2;self.refused(v)

    def test_missing_unknown_and_boolean_fields(self):
        for field in ('producer_timing','reader_timing'):
            for change in ('missing','unknown','boolean'):
                v=row();t=v[field]
                if change=='missing':del t['budget_ms']
                elif change=='unknown':t['extra']=0
                else:t['completed_window_elapsed_ms'][0]=True
                self.refused(v)

    def test_reader_always_has_initial_window(self):
        v=failed();v['progress_failure']['last']=None;v['progress_failure']['reason']='GlobalDeadline';self.refused(v)
        for bad in (None,1,True):
            v=row();v['reader_timing']['elapsed_before_first_window_ms']=bad;self.refused(v)

    def test_current_and_before_must_pair(self):
        for key in ('elapsed_before_first_window_ms','current_window_elapsed_ms'):
            v=row();v['reader_timing'][key]=None;self.refused(v)

    def test_failed_timing_matches_exact_stage(self):
        v=failed();v['progress_timing']['total_elapsed_ms']+=1;self.refused(v)
        v=failed();v['progress_failure']['last']['phase']='Shutdown';self.refused(v)
        v=failed();v['progress_failure']['last']['owner']=1;self.refused(v)
        v=failed();v['progress_failure']['last']['last_native']=dict(owner=1,job_id=1,sequence=1,stage='ReturnServe');self.refused(v)

    def test_producer_diagnostic_cannot_be_reader(self):
        v=failed(False);v['first_failure']='CompletedReopen';self.refused(v)

    def test_failure_and_success_incompatible(self):
        v=failed();v['result']='passed';self.refused(v)

    def test_maximum_valid_diagnostic_line_bound(self):
        v=failed();a={k:600000000 for k in M.AUTHORITY_OPTIONAL_MICROS}
        a.update(stage=max(M.AUTHORITY_STAGES,key=len),check_site=max(M.AUTHORITY_CHECK_SITES,key=len),checkpoint=max(M.AUTHORITY_CHECKPOINTS,key=len),selected_limit='Exchange',exchange_cost={k:(1000000 if k.endswith('_calls') else 600000000) for k in M.AUTHORITY_COST_FIELDS},clamped=True,incomplete=True,pre_budget_callback_calls=1,pre_budget_callback_us=600000000)
        v['financial_diagnostic']=dict(schema=1,stage='NativeAuthorityVerifyActive',component='Authority',error_class=max(M.FINANCIAL_ERRORS,key=len),commit_state='OutcomeUncertain',current_timing=None,authority_call=a)
        # Largest digit width allowed across finite timing vectors while keeping exact sums.
        for field in ('producer_timing','reader_timing'):
            t=v[field];n=len(t['completed_window_elapsed_ms']);before=0 if field=='reader_timing' else 100000;t.update(elapsed_before_first_window_ms=before,current_window_elapsed_ms=100000,completed_window_elapsed_ms=[50000]*n,total_elapsed_ms=before+100000+50000*n)
        v['progress_timing']=copy.deepcopy(v['reader_timing'])
        M.validate(v)
        encoded=M.PREFIX+json.dumps(v,sort_keys=True,separators=(',',':')).encode()
        self.assertLessEqual(len(encoded),4096,len(encoded))

    def test_success_requires_both_complete_timings(self):
        for key in ('producer_timing','reader_timing'):
            v=row();v[key]=None;self.refused(v)
            v=row();v[key]['completed_window_elapsed_ms'].pop();v[key]['total_elapsed_ms']-=1;self.refused(v)

    def test_no_marker_reader_watchdog_keeps_completed_reopen_role(self):
        v=failed();v['progress_failure']['last']=dict(window=0,owner=0,phase='ReaderHostOpen',call='Begin',last_native=None)
        t=dict(budget_ms=1800000,elapsed_before_first_window_ms=0,completed_window_elapsed_ms=[],current_window_elapsed_ms=120001,total_elapsed_ms=120001,clamped=False)
        v['reader_timing']=copy.deepcopy(t);v['progress_timing']=copy.deepcopy(t)
        M.validate(v)
        v['first_failure']='FinalTransactionRetention'
        self.refused(v)

    def test_each_reader_phase_is_exact(self):
        for index,(owner,phase) in enumerate(M.READER_PROGRESS_WINDOWS):
            record=dict(reason='PhaseDeadline',last=dict(window=index,owner=owner,phase=phase,call='Begin',last_native=None))
            M.validate_progress_failure(record,True)
            record['last']['window']=True
            with self.assertRaises(ValueError):M.validate_progress_failure(record,True)

    def test_unknown_top_level_fields_refused(self):
        v=row();v['extra']='not projected';self.refused(v)
        v=row();del v['fixture_profile'];self.refused(v)

    def projected_child(self, value, status=0, expected_selector=None):
        with tempfile.TemporaryDirectory(prefix='closed-financial-v2-') as directory:
            path=pathlib.Path(directory)/'fixture'
            body='#!'+sys.executable+'\nimport sys\n'
            body+='assert sys.argv[1] == '+repr(expected_selector or M.TEST)+'\n'
            body+='print("RAW_SENTINEL_MUST_NOT_ESCAPE")\n'
            body+='print('+repr(M.PREFIX.decode()+json.dumps(value,separators=(',',':')))+')\n'
            body+='sys.exit('+str(status)+')\n'
            path.write_text(body);path.chmod(0o700)
            output=io.StringIO();failure=None
            with contextlib.redirect_stdout(output):
                try:M.run(str(path))
                except Exception as error:failure=type(error).__name__
            self.assertNotIn('RAW_SENTINEL_MUST_NOT_ESCAPE',output.getvalue())
            return failure,output.getvalue()

    def test_controlled_new_selector_success(self):
        error,output=self.projected_child(row())
        self.assertIsNone(error)
        self.assertIn('CI_FINANCIAL_RESULT passed=true',output)

    def test_controlled_reader_failure_retains_producer_timing(self):
        error,output=self.projected_child(failed(),1)
        self.assertIsNotNone(error)
        self.assertIn('"producer_timing":',output)
        self.assertIn('"ReaderShutdown"',output)

    def test_controlled_old_schema_and_selector_rejected(self):
        value=row();value['schema']=4
        error,output=self.projected_child(value)
        self.assertIsNotNone(error);self.assertNotIn('passed=true',output)
        error,output=self.projected_child(row(),expected_selector=M.TEST.removesuffix('_v2'))
        self.assertIsNotNone(error);self.assertNotIn('passed=true',output)

    def test_duplicate_json_keys_refused(self):
        with self.assertRaises(ValueError):json.loads('{"schema":5,"schema":5}',object_pairs_hook=M.unique_object)


if __name__ == '__main__':unittest.main()
