"""Pure closed-protocol regressions; no native product, credentials or container."""
import contextlib
import importlib.util
import io
import json
import pathlib
import os
import re
import socket
import stat
import tempfile
import sys
import unittest
from unittest import mock
ROOT=pathlib.Path(__file__).resolve().parents[1]
spec=importlib.util.spec_from_file_location('fixture_container_tested',ROOT/'ci-financial-container.py')
M=importlib.util.module_from_spec(spec);sys.modules[spec.name]=M;spec.loader.exec_module(M)

class FixtureDiagnostics(unittest.TestCase):
    def value(self):
        return dict(version=1,phase='child_stage',reason='ChildExit',next=12,expected=200,
                    process_cleanup=True,root_cleanup=True)
    def line(self,value):
        return M.DIAGNOSTIC+json.dumps(value,separators=(',',':')).encode()
    def test_real_pathname_socket_bind_in_container_shaped_private_tree(self):
        source=next((ROOT.parent/'crates/wholepact-native-host/src').rglob('coordinated_full_fixture_v1.rs')).read_text()
        prefix=re.search(r'const FULL_ROOT_PREFIX: &str = "([a-z-]+)";',source).group(1)
        with tempfile.TemporaryDirectory(prefix='wp-bind---',dir='/tmp') as base:
            self.assertEqual(len(base),len('/ci-fixture/full-parent'))
            for outer,binds in [('full-original-',False),(prefix,True)]:
                parent=pathlib.Path(base)/(outer+'aaaaaa')
                endpoint=parent/'wholepact-born-manual-ipc-bbbbbb'
                parent.mkdir(mode=0o700);endpoint.mkdir(mode=0o700)
                for directory in (pathlib.Path(base),parent,endpoint):
                    meta=directory.lstat()
                    self.assertTrue(stat.S_ISDIR(meta.st_mode))
                    self.assertEqual(stat.S_IMODE(meta.st_mode),0o700)
                    self.assertEqual(meta.st_uid,os.geteuid())
                path=str(endpoint/('requests-'+'00'*12+'.sock'))
                with socket.socket(socket.AF_UNIX,socket.SOCK_STREAM) as listener:
                    if binds:
                        self.assertEqual(len(path),104)
                        listener.bind(path)
                        self.assertEqual(listener.getsockname(),path)
                        self.assertTrue(stat.S_ISSOCK(os.lstat(path).st_mode))
                        self.assertEqual(os.lstat(path).st_uid,os.geteuid())
                    else:
                        self.assertEqual(len(path),116)
                        with self.assertRaises(OSError):listener.bind(path)

    def test_closed_rust_reason_enum_and_emission_phases_match_parser(self):
        source=next((ROOT.parent/'crates/wholepact-native-host/src').rglob('sequential_construction_v3_qualification.rs')).read_text()
        enum=re.search(r'enum HarnessFailureReason \{([^}]+)\}',source).group(1)
        reasons=set(re.findall(r'([A-Za-z0-9]+),',enum))
        self.assertEqual(reasons|{'Setup'},set(M.FIXTURE_REASONS))
        source=next((ROOT.parent/'crates/wholepact-native-host/src').rglob('coordinated_full_fixture_v1.rs')).read_text()
        phases=set(re.findall(r'phase = "([a-z_]+)"',source))
        phases.update(re.findall(r'=> "(post_[a-z_]+)"',source))
        self.assertEqual(phases|{'child_identity','child_directory','child_exec'},set(M.FIXTURE_PHASES))

    def test_every_closed_phase_and_reason(self):
        for phase in M.FIXTURE_PHASES:
            for reason in M.FIXTURE_REASONS:
                value=self.value()|dict(phase=phase,reason=reason)
                self.assertEqual(M.fixture_diagnostic(self.line(value)),value)
    def test_reject_unknown_private_text_wrong_types_and_counter_overflow(self):
        for field,values in dict(version=[True,2,'1'],phase=['private-source',[],None],
            reason=['password=private',[],None],next=[True,-1,201,1.5],expected=[True,-1,4097],
            process_cleanup=[1,'true',None],root_cleanup=[0,'false',None]).items():
            for replacement in values:
                value=self.value()|{field:replacement}
                with self.subTest(field=field,value=replacement), self.assertRaises(Exception):
                    M.fixture_diagnostic(self.line(value))
        for value in (self.value()|{'transcript':'private'}, {k:v for k,v in self.value().items() if k!='reason'}):
            with self.assertRaises(Exception):M.fixture_diagnostic(self.line(value))
    def test_no_raw_line_or_error_is_forwarded(self):
        parent=M.FixtureParent.__new__(M.FixtureParent)
        parent.deadline=100;parent.pending=bytearray();parent.total=0;parent.diagnostic=None
        parent.process=mock.Mock();parent.process.stdout.fileno.return_value=42
        selector=mock.MagicMock();selector.__enter__.return_value=selector;selector.select.return_value=[True]
        line=self.line(self.value())
        blocks=[b'private-child-output\n'+line[:15],line[15:]+b'\nprivate-trailer\n']
        out=io.StringIO()
        with mock.patch.object(M.selectors,'DefaultSelector',return_value=selector), \
             mock.patch.object(M.time,'monotonic_ns',return_value=0), \
             mock.patch.object(M.os,'read',side_effect=blocks),contextlib.redirect_stdout(out):
            with self.assertRaises(Exception):parent.wait_marker(M.READY)
        self.assertEqual(out.getvalue().strip(),line.decode())
        self.assertNotIn('private-child-output',out.getvalue())
        self.assertNotIn('private-trailer',out.getvalue())
    def test_supervisor_accepts_exact_same_closed_phase_set(self):
        spec=importlib.util.spec_from_file_location('fixture_supervisor_tested',ROOT/'ci-financial-supervisor.py')
        supervisor=importlib.util.module_from_spec(spec);spec.loader.exec_module(supervisor)
        self.assertEqual(supervisor.FIXTURE_PHASES,M.FIXTURE_PHASES)
        for phase in M.FIXTURE_PHASES:
            records=supervisor.RuntimeRecords('full')
            value=self.value()|{'phase':phase}
            with contextlib.redirect_stdout(io.StringIO()):
                records(b'CI_FINANCIAL_FIXTURE_DIAGNOSTIC '+json.dumps(value).encode())
            self.assertEqual(records.fixture_diagnostic,value)

    def test_public_ready_marker_is_framed_after_libtest_prefix(self):
        source=next((ROOT.parent/'crates/wholepact-native-host/src').rglob('coordinated_full_fixture_v1.rs')).read_text()
        literal=re.search(r'const PUBLIC_READY_LINE: &str = "([^"\n]+)";',source).group(1)
        line=literal.encode().decode('unicode_escape').encode()
        self.assertEqual(line,b'\n'+M.READY)
        parent=M.FixtureParent.__new__(M.FixtureParent)
        parent.deadline=100;parent.pending=bytearray();parent.total=0;parent.diagnostic=None
        parent.process=mock.Mock();parent.process.stdout.fileno.return_value=42
        selector=mock.MagicMock();selector.__enter__.return_value=selector;selector.select.return_value=[True]
        out=io.StringIO()
        with mock.patch.object(M.selectors,'DefaultSelector',return_value=selector), \
             mock.patch.object(M.time,'monotonic_ns',return_value=0), \
             mock.patch.object(M.os,'read',return_value=b'test fixture ... '+line+b'\n'),contextlib.redirect_stdout(out):
            parent.wait_marker(M.READY)
        self.assertEqual(out.getvalue(),'')

    def test_malformed_diagnostic_emits_nothing(self):
        out=io.StringIO()
        with contextlib.redirect_stdout(out),self.assertRaises(Exception):
            M.emit_fixture_diagnostic(M.fixture_diagnostic(self.line(self.value()|{'reason':'secret'})))
        self.assertEqual(out.getvalue(),'')


class CachedProgressDiagnostics(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        spec=importlib.util.spec_from_file_location('progress_supervisor_tested',ROOT/'ci-financial-supervisor.py')
        cls.S=importlib.util.module_from_spec(spec);spec.loader.exec_module(cls.S)
    def value(self):return M.C.cached_progress_diagnostic([],M.C.EXTERNAL_PROFILE)
    def record(self,kind,role='Coordinator',facts=None):
        return dict(schema=1,profile=M.C.EXTERNAL_PROFILE,role=role,sequence=1,
                    elapsed_ns=0,kind=kind,facts={} if facts is None else facts)
    def line(self,value):return b'CI_FINANCIAL_PROGRESS_DIAGNOSTIC '+json.dumps(value).encode()
    def candidate(self):
        return b'CI_FINANCIAL_CANDIDATE '+json.dumps(dict(schema=1,profile=M.C.EXTERNAL_PROFILE,
            native_oracle_verified=True,fixture_cleaned=True,display_cleaned=True,
            public_chain_verified=False,dispatch_attempted=False)).encode()
    def test_fixed_order_counts_zero_one_and_saturating_duplicates(self):
        records=[]
        for owner in ('Signer1','Signer2'):
            for step in M.C.SIGNER_STEPS:
                records.append(self.record('SignerMilestone',owner,{'owner':owner,'step':step}))
        records += [self.record('HostMilestone','Host',{'step':s}) for s in M.C.HOST_STEPS]
        records += [self.record(s) for s in M.C.NORMAL_DIAGNOSTIC_STEPS]
        for repeats,expected in ((0,0),(1,1),(2,2),(5,2)):
            value=M.C.cached_progress_diagnostic(records*repeats,M.C.EXTERNAL_PROFILE)
            self.assertEqual(value,dict(version=1,signer_counts=[[expected]*len(M.C.SIGNER_STEPS) for _ in range(2)],
                host_counts=[expected]*len(M.C.HOST_STEPS),normal_counts=[expected]*4,
                phase_counts=[0]*len(M.C.DIAGNOSTIC_PHASES)))
        self.assertEqual(M.C.NORMAL_DIAGNOSTIC_STEPS,('NormalFinishAdmitted','PtyHeld','PtyReleased','NormalFinished'))
    def test_phase_counts_use_only_validated_frames_fixed_order_and_bounded_size(self):
        self.assertEqual(M.C.DIAGNOSTIC_PHASES,tuple(sorted(M.C.PHASES)))
        snapshots=[]
        for phase in M.C.DIAGNOSTIC_PHASES:
            facts=dict(phase=phase,subphase='None',owner=None,view_generation=1,
                focused=True,secret_input=False,host_input=False,pixels_per_point=1,
                viewport=[1280,800],widgets=[])
            snapshots.append(self.record('UiSnapshot',facts=facts))
        for repeats,expected in ((1,1),(3,2)):
            value=M.C.cached_progress_diagnostic(snapshots*repeats,M.C.EXTERNAL_PROFILE)
            self.assertEqual(value['phase_counts'],[expected]*len(M.C.DIAGNOSTIC_PHASES))
            self.assertEqual(value['signer_counts'],self.value()['signer_counts'])
            self.assertLess(len(self.line(value)),8192)
        for record in (snapshots[0]|{'role':'Host'},
                       snapshots[0]|{'facts':snapshots[0]['facts']|{'phase':'private'}}):
            with self.assertRaises(Exception):M.C.cached_progress_diagnostic([record],M.C.EXTERNAL_PROFILE)
        for delta in (-1,1):
            value=self.value();value['phase_counts']=[0]*(len(M.C.DIAGNOSTIC_PHASES)+delta)
            with self.assertRaises(Exception):M.C.validate_progress_diagnostic(value)

    def test_invalid_cache_bounds_profile_and_incomplete_failure_record(self):
        for records,profile in ((None,M.C.EXTERNAL_PROFILE),([], 'private'),
                ([{}]*(M.C.MAX_RECORDS+1),M.C.EXTERNAL_PROFILE)):
            with self.assertRaises(Exception):M.C.cached_progress_diagnostic(records,profile)
        records=self.S.RuntimeRecords('external');records(self.line(self.value()))
        with self.assertRaises(self.S.Failure):records.finish(1)
        without=self.S.RuntimeRecords('external');out=io.StringIO()
        with contextlib.redirect_stdout(out):
            without(b'CI_FINANCIAL_RESULT '+json.dumps(self.S.P.failure('normal_finish')).encode())
        self.assertEqual(without.finish(1),self.S.P.failure('normal_finish'))
        self.assertNotIn('PROGRESS_DIAGNOSTIC',out.getvalue())

    def test_roles_record_shape_and_unknown_data_fail_closed(self):
        invalid=[self.record('NormalFinished','Host'),self.record('HostMilestone','Signer1',{'step':'Owner1SigningRetired'}),
                 self.record('SignerMilestone','Signer1',{'owner':'Signer2','step':'EntryOpened'}),
                 self.record('HostMilestone','Host',{'step':'private'}),self.record('NormalFinished')|{'private':'secret'}]
        for record in invalid:
            with self.subTest(kind=record['kind']),self.assertRaises(Exception):
                M.C.cached_progress_diagnostic([record],M.C.EXTERNAL_PROFILE)
    def test_exact_keys_dimensions_types_bounds_and_no_private_echo(self):
        bad=[self.value()|{'private':'secret'},self.value()|{'version':True},self.value()|{'version':2},
             {k:v for k,v in self.value().items() if k!='host_counts'}]
        for key in ('signer_counts','host_counts','normal_counts','phase_counts'):
            bad.extend([self.value()|{key:None},self.value()|{key:[]},self.value()|{key:'private'}])
        for replacement in (True,-1,3,1.0,'secret',None,{},[]):
            value=self.value();value['signer_counts'][0][0]=replacement;bad.append(value)
            value=self.value();value['host_counts'][0]=replacement;bad.append(value)
            value=self.value();value['normal_counts'][0]=replacement;bad.append(value)
            value=self.value();value['phase_counts'][0]=replacement;bad.append(value)
        value=self.value();value['signer_counts'][0].append(0);bad.append(value)
        for value in bad:
            with self.assertRaises(Exception):M.C.validate_progress_diagnostic(value)
            stream=io.StringIO();records=self.S.RuntimeRecords('external')
            with contextlib.redirect_stdout(stream),self.assertRaises(self.S.Failure):records(self.line(value))
            self.assertEqual(stream.getvalue(),'')
    def test_supervisor_buffers_once_until_failure_and_cannot_enable_success(self):
        records=self.S.RuntimeRecords('external');out=io.StringIO()
        with contextlib.redirect_stdout(out):records(self.line(self.value()))
        self.assertEqual(out.getvalue(),'')
        with self.assertRaises(self.S.Failure):records(self.line(self.value()))
        with self.assertRaises(self.S.Failure):records(self.candidate())
        with contextlib.redirect_stdout(out):
            records(b'CI_FINANCIAL_RESULT '+json.dumps(self.S.P.failure('normal_finish')).encode())
        lines=out.getvalue().splitlines()
        self.assertEqual(len(lines),2);self.assertTrue(lines[0].startswith('CI_FINANCIAL_PROGRESS_DIAGNOSTIC '))
        self.assertTrue(lines[1].startswith('CI_FINANCIAL_FAILURE '))
        self.assertEqual(records.finish(1),self.S.P.failure('normal_finish'))
        with self.assertRaises(self.S.Failure):records(self.line(self.value()))
        clean=self.S.RuntimeRecords('external');clean(self.candidate());self.assertTrue(clean.finish(0)['native_oracle_verified'])
    def test_duplicate_json_key_rejected_without_emission(self):
        line=self.line(self.value()).replace(b'"version": 1',b'"version": 1, "version": 1')
        stream=io.StringIO()
        with contextlib.redirect_stdout(stream),self.assertRaises(Exception):self.S.RuntimeRecords('external')(line)
        self.assertEqual(stream.getvalue(),'')
    def test_container_uses_cached_records_only_and_invalid_cache_emits_nothing(self):
        flow=mock.Mock();flow.expected_profile=M.C.EXTERNAL_PROFILE
        flow.records=[self.record('NormalFinished')]
        out=io.StringIO()
        with contextlib.redirect_stdout(out):M.emit_cached_progress_failure(flow)
        value=json.loads(out.getvalue().split(' ',1)[1]);self.assertEqual(value['normal_counts'],[0,0,0,1])
        flow.observer.read.assert_not_called();flow.snapshot.assert_not_called()
        flow.records=[self.record('NormalFinished')|{'private':'secret'}];out=io.StringIO()
        with contextlib.redirect_stdout(out):M.emit_cached_progress_failure(flow)
        self.assertEqual(out.getvalue(),'')
    def test_main_failure_only_diagnostic_and_original_failure_preserved(self):
        for fail,invalid in ((False,False),(True,False),(True,True)):
            with self.subTest(fail=fail,invalid=invalid),contextlib.ExitStack() as stack:
                session=mock.Mock();session.flow.location=None
                session.flow.expected_profile=M.C.EXTERNAL_PROFILE
                session.flow.records=[self.record('NormalFinished')]
                if invalid:session.flow.records[0]['private']='secret'
                if fail:session.run.side_effect=M.C.Rejected('normal_finish')
                else:session.run.return_value=([],123,0)
                for obj,name in ((M,'root_setup'),(M,'FixtureParent'),(M,'write_account'),(M.os,'setgroups'),
                    (M.os,'setresgid'),(M.os,'setresuid'),(M.K,'harden_process'),(M.F.Fixture,'load'),
                    (M.OUT,'validate_completed')):stack.enter_context(mock.patch.object(obj,name))
                stack.enter_context(mock.patch.object(M,'NativeSession',return_value=session))
                stack.enter_context(mock.patch.object(M,'secure_file',return_value=(b'{}',None)))
                stack.enter_context(mock.patch.object(M.pathlib.Path,'iterdir',return_value=[pathlib.Path('1')]))
                stack.enter_context(mock.patch.object(M.sys,'argv',['container']))
                output=io.StringIO();stack.enter_context(contextlib.redirect_stdout(output))
                if fail:
                    with self.assertRaises(SystemExit):M.main()
                else:M.main()
                text=output.getvalue()
                self.assertEqual(text.count('CI_FINANCIAL_PROGRESS_DIAGNOSTIC '),int(fail and not invalid))
                self.assertNotIn('secret',text)
                if fail:self.assertIn('"code":"normal_finish"',text)
                else:self.assertIn('CI_FINANCIAL_CANDIDATE ',text)

if __name__=='__main__':unittest.main()

