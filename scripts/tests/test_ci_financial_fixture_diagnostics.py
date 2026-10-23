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
                host_observation=dict(revision=0,nonws_end=0,context_valid=True,entry='Idle',editor=None,view=None),
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
        flow.records=[]  # Stale flow cache must not control failure reporting.
        flow.observer.failure_diagnostics.return_value={'progress':M.C.cached_progress_diagnostic([self.record('NormalFinished')],M.C.EXTERNAL_PROFILE)}
        out=io.StringIO()
        with contextlib.redirect_stdout(out):M.emit_cached_progress_failure(flow)
        value=json.loads(out.getvalue().split(' ',1)[1]);self.assertEqual(value['normal_counts'],[0,0,0,1])
        flow.observer.read.assert_not_called();flow.snapshot.assert_not_called()
        flow.observer.failure_diagnostics.return_value={'progress':{'private':'secret'}};out=io.StringIO()
        with contextlib.redirect_stdout(out):M.emit_cached_progress_failure(flow)
        self.assertEqual(out.getvalue(),'')
    def test_main_failure_only_diagnostic_and_original_failure_preserved(self):
        for fail,invalid in ((False,False),(True,False),(True,True)):
            with self.subTest(fail=fail,invalid=invalid),contextlib.ExitStack() as stack:
                session=mock.Mock();session.flow.location=None
                session.flow.expected_profile=M.C.EXTERNAL_PROFILE
                session.flow.records=[self.record('NormalFinished')]
                session.flow.observer.failure_diagnostics.return_value={'progress':M.C.cached_progress_diagnostic(session.flow.records,M.C.EXTERNAL_PROFILE)}
                if invalid:session.flow.observer.failure_diagnostics.return_value={'progress':{'private':'secret'}}
                if fail:session.run.side_effect=M.C.Rejected('normal_finish')
                else:session.run.return_value=([],123,0)
                for obj,name in ((M,'root_setup'),(M,'FixtureParent'),(M,'write_account'),(M.os,'setgroups'),
                    (M.os,'setresgid'),(M.os,'setresuid'),(M.K,'harden_process'),(M.F.Fixture,'load'),
                    (M.OUT,'validate_completed')):stack.enter_context(mock.patch.object(obj,name))
                stack.enter_context(mock.patch.object(M,'root_setup',return_value=(b'',M.C.EXTERNAL_PROFILE)))
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


class ReviewerArtifactTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup)
        self.base=pathlib.Path(self.temp.name);self.root=self.base/'f-test';self.root.mkdir(mode=0o700)
        self.patch=mock.patch.object(M.F,'ARTIFACT_PARENT',self.base);self.patch.start();self.addCleanup(self.patch.stop)
        self.check=mock.patch.object(M.F.Fixture,'check');self.check.start();self.addCleanup(self.check.stop)
        self.fixture=M.F.Fixture.__new__(M.F.Fixture)
        self.fixture._fixture_root=self.root;self.fixture._artifact_root_identity=None
        self.choices=dict(submission_operation_id='synthetic-original-delivery-admission-v2',
            provider=dict(source_id='synthetic-source',endpoint='https://example.invalid',
                trust_profile='single_tls_provider_report_not_consensus'),route={'kind':'direct'},
            minimum_expiry_margin_blocks=1,maximum_fresh_admission_lifetime_ms=120000,
            maximum_explicitly_approved_attempts=3)
        protected=self.base/'protected-profile';protected.mkdir(mode=0o700)
        data={'delivery_choices':self.choices,'profile':str(protected),'sources':[]}
        for key,name in [('session_commands_file','coordinated-fixture-session-commands.json'),
                         ('delivery_choices_file','coordinated-fixture-delivery-choices.json'),
                         ('wallet_setup_file','coordinated-fixture-wallet-setup.json'),
                         ('host_password_file','coordinated-fixture-host-password.private'),
                         ('source_password_file','coordinated-fixture-source-password.private')]:
            path=self.root/name;path.write_text(json.dumps(self.choices if key=='delivery_choices_file' else {}));path.chmod(0o600);data[key]=str(path)
        for index in (1,2):
            account=str(index)*64;entry={'account_id':account};path=self.root/f'coordinated-fixture-source-{index}-entry.json'
            path.write_text(json.dumps(entry));path.chmod(0o600)
            data['sources'].append({'role':f'signer{index}','entry_selection':entry,'entry_selection_file':str(path),
                'reopen_selector':{'account_id':account},'original_capture':{'scope':{'account_id':account,
                'participant_id':f'synthetic-participant-{index}'},'request':{'operation_id':f'private-original-native-capture-{index}'}}})
        self.fixture._data=data
    def test_native_path_reader_receives_private_exact_schema_for_each_owner(self):
        native=(ROOT.parent/'crates/wholepact-native-host/src/host.rs').read_text()
        body=native[native.index('fn read_json<T:'):native.index('fn pair(&self)')]
        self.assertIn('files::read_artifact(&path, 262_144)',body)
        paths=[]
        for index in (1,2):
            path=pathlib.Path(self.fixture.reviewer_selection_path(f'Signer{index}'));paths.append(path)
            self.assertTrue(path.is_absolute());self.assertEqual(path.parent,self.root)
            meta=path.stat();self.assertEqual(stat.S_IMODE(meta.st_mode),0o600);self.assertEqual(meta.st_uid,os.getuid());self.assertEqual(meta.st_nlink,1)
            raw=M.F.private_bytes(path,262144);value=json.loads(raw)
            self.assertEqual(value,dict(import_operation_id=f'full-native-import-{index}',
                redisclosure_operation_id=f'full-native-redisclose-{index}',account_id=str(index)*64,
                participant_id=f'synthetic-participant-{index}',choices=self.choices))
        self.assertNotEqual(paths[0],paths[1])
    def test_flow_returns_path_once_never_inline_or_recreates(self):
        flow=M.FLOW.FullFlow.__new__(M.FLOW.FullFlow)
        flow.startup_index=len(M.FLOW.HOST_STARTUP) # genuine startup tested separately
        flow.fixture=self.fixture;flow.last_rendered=None;flow.host_paths=set();flow.challenges=set()
        flow.records=[];flow.reviewer_index=0;flow.continue_index=flow.result_index=0
        text='Exact coordinated reviewer selection JSON'
        kind,value=flow.expected_host_line(text)
        self.assertEqual(kind,'public');self.assertTrue(pathlib.Path(value).is_absolute())
        before=pathlib.Path(value).stat().st_ino
        self.assertIsNone(flow.expected_host_line(text));self.assertEqual(flow.reviewer_index,1)
        self.assertEqual(pathlib.Path(value).stat().st_ino,before)
        with self.assertRaises(Exception):self.fixture.reviewer_selection_path('Signer1')
    def test_existing_symlink_and_hardlink_destinations_never_overwritten(self):
        target=self.root/'coordinated-reviewer-selection-1.json';outside=self.base/'untouched';outside.write_bytes(b'original')
        for kind in ('existing','symlink','hardlink'):
            with self.subTest(kind=kind):
                if kind=='existing':target.write_bytes(b'existing')
                elif kind=='symlink':target.symlink_to(outside)
                else:os.link(outside,target)
                with self.assertRaises(Exception):self.fixture.reviewer_selection_path('Signer1')
                self.assertEqual(outside.read_bytes(),b'original');target.unlink()
    def test_missing_alias_symlink_handoff_and_rebound_root_rejected(self):
        path=pathlib.Path(self.fixture._data['delivery_choices_file']);saved=path.read_bytes();path.unlink()
        with self.assertRaises(Exception):self.fixture.reviewer_selection_path('Signer1')
        path.write_bytes(saved);path.chmod(0o600)
        renamed=self.root/'alias.json';path.rename(renamed);path.symlink_to(renamed)
        with self.assertRaises(Exception):self.fixture.reviewer_selection_path('Signer1')
        path.unlink();renamed.rename(path)
        fd=self.fixture._artifact_root_fd();os.close(fd)
        old=self.base/'old';self.root.rename(old);self.root.mkdir(mode=0o700)
        with self.assertRaises(Exception):self.fixture.reviewer_selection_path('Signer1')
    def test_identity_choices_and_original_operation_collisions_fail_before_creation(self):
        cases=[('scope',lambda:self.fixture._data['sources'][0]['original_capture']['scope'].update(account_id='f'*64)),
               ('participant',lambda:self.fixture._data['sources'][0]['original_capture']['scope'].update(participant_id='synthetic-participant-2')),
               ('operation',lambda:self.fixture._data['sources'][0]['original_capture']['request'].update(operation_id='full-native-import-1')),
               ('choices',lambda:self.choices.update(maximum_explicitly_approved_attempts=True))]
        import copy
        original=copy.deepcopy(self.fixture._data)
        for name,change in cases:
            with self.subTest(name=name):
                self.fixture._data=copy.deepcopy(original);self.choices=self.fixture._data['delivery_choices'];change()
                with self.assertRaises(Exception):self.fixture.reviewer_selection_path('Signer1')
                self.assertFalse((self.root/'coordinated-reviewer-selection-1.json').exists())
    def test_authoritative_file_mismatch_and_entry_alias_rejected(self):
        entry=pathlib.Path(self.fixture._data['sources'][0]['entry_selection_file'])
        entry.write_text('{}')
        with self.assertRaises(Exception):self.fixture.reviewer_selection_path('Signer1')
        entry.write_text(json.dumps(self.fixture._data['sources'][0]['entry_selection']))
        alias=self.root/'entry-alias.json';entry.rename(alias)
        self.fixture._data['sources'][0]['entry_selection_file']=str(alias)
        with self.assertRaises(Exception):self.fixture.reviewer_selection_path('Signer1')
        self.assertFalse((self.root/'coordinated-reviewer-selection-1.json').exists())
    def test_profile_symlink_alias_to_artifact_root_rejected(self):
        alias=self.base/'profile-alias';alias.symlink_to(self.root,target_is_directory=True)
        self.fixture._data['profile']=str(alias)
        with self.assertRaises(Exception):self.fixture.reviewer_selection_path('Signer1')
        self.assertFalse((self.root/'coordinated-reviewer-selection-1.json').exists())
    def test_artifact_root_beneath_protected_profile_rejected(self):
        self.fixture._data['profile']=str(self.base)
        with self.assertRaises(Exception):self.fixture.reviewer_selection_path('Signer1')
        self.assertFalse((self.root/'coordinated-reviewer-selection-1.json').exists())
    def test_artifact_never_created_inside_protected_profile(self):
        self.fixture._data['profile']=str(self.root)
        with self.assertRaises(Exception):self.fixture.reviewer_selection_path('Signer1')
        self.assertFalse((self.root/'coordinated-reviewer-selection-1.json').exists())
    def test_creation_failure_keeps_input_counter_and_original_file(self):
        flow=M.FLOW.FullFlow.__new__(M.FLOW.FullFlow)
        flow.startup_index=len(M.FLOW.HOST_STARTUP) # genuine startup tested separately
        flow.fixture=self.fixture;flow.last_rendered=None;flow.host_paths=set();flow.records=[];flow.reviewer_index=0
        target=self.root/'coordinated-reviewer-selection-1.json';target.write_text('keep')
        with self.assertRaises(Exception):flow.expected_host_line('Exact coordinated reviewer selection JSON')
        self.assertEqual(flow.reviewer_index,0);self.assertEqual(target.read_text(),'keep')
    def test_owned_disposable_root_cleanup_covers_artifacts_without_touching_profile_elsewhere(self):
        import shutil
        protected=self.base/'protected-profile';sentinel=protected/'keep';sentinel.write_text('untouched')
        self.fixture._data['profile']=str(protected)
        path=pathlib.Path(self.fixture.reviewer_selection_path('Signer1'))
        shutil.rmtree(self.root) # test-owned root only; same containment as native root cleanup
        self.assertFalse(path.exists());self.assertEqual(sentinel.read_text(),'untouched')

class ObservationTimingProjectionTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        spec=importlib.util.spec_from_file_location('timing_supervisor_tested',ROOT/'ci-financial-supervisor.py')
        cls.S=importlib.util.module_from_spec(spec);spec.loader.exec_module(cls.S)
    def value(self):
        return dict(version=1,availability='Observed',observer_remaining_ns=1,
                    coordinator_last_elapsed_ns=20,last_phase=dict(phase='V3Preparing',subphase='None',
                    owner=None,first_elapsed_ns=10,last_elapsed_ns=20,snapshot_count=2))
    def line(self,value):return b'CI_FINANCIAL_OBSERVATION_TIMING_DIAGNOSTIC '+json.dumps(value).encode()
    def failed(self,profile):return b'CI_FINANCIAL_RESULT '+json.dumps(self.S.P.failure('deadline',profile)).encode()
    def candidate(self,profile):return b'CI_FINANCIAL_CANDIDATE '+json.dumps(dict(schema=1,profile=profile,
        native_oracle_verified=True,fixture_cleaned=True,display_cleaned=True,public_chain_verified=False,dispatch_attempted=False)).encode()
    def test_valid_timing_is_held_until_failure_for_both_profiles(self):
        for profile in (M.C.EXTERNAL_PROFILE,M.C.SEMANTIC_PROFILE):
            for value in (self.value(),dict(version=1,availability='Unavailable',observer_remaining_ns=None,coordinator_last_elapsed_ns=None,last_phase=None)):
                records=self.S.RuntimeRecords('external',profile);out=io.StringIO()
                with contextlib.redirect_stdout(out):
                    records(self.line(value));self.assertEqual(out.getvalue(),'')
                    records(self.failed(profile))
                self.assertEqual(records.finish(1),self.S.P.failure('deadline',profile))
                lines=out.getvalue().splitlines();self.assertEqual(len(lines),2)
                self.assertEqual(json.loads(lines[0].split(' ',1)[1]),value)
                self.assertTrue(lines[1].startswith('CI_FINANCIAL_FAILURE '))
    def test_timing_cannot_complete_runtime_or_accompany_success_or_repeat(self):
        records=self.S.RuntimeRecords('external');records(self.line(self.value()))
        for action in (lambda:records.finish(1),lambda:records(self.candidate(M.C.EXTERNAL_PROFILE)),lambda:records(self.line(self.value()))):
            with self.assertRaises(self.S.Failure):action()
    def test_old_failure_and_success_remain_unchanged_without_timing(self):
        for profile in (M.C.EXTERNAL_PROFILE,M.C.SEMANTIC_PROFILE):
            good=self.S.RuntimeRecords('external',profile);good(self.candidate(profile));self.assertTrue(good.finish(0)['native_oracle_verified'])
            failed=self.S.RuntimeRecords('external',profile);out=io.StringIO()
            with contextlib.redirect_stdout(out):failed(self.failed(profile))
            self.assertNotIn('TIMING',out.getvalue());self.assertEqual(failed.finish(1)['code'],'deadline')
    def test_unknown_fields_private_strings_types_and_bounds_fail_without_output(self):
        valid=self.value();bad=[valid|{'private':'secret/path'},valid|{'version':True},valid|{'version':2},
            valid|{'availability':'secret'},valid|{'observer_remaining_ns':True},valid|{'observer_remaining_ns':0},
            valid|{'observer_remaining_ns':M.C.ORIGINAL_NS+1},valid|{'coordinator_last_elapsed_ns':True},
            valid|{'coordinator_last_elapsed_ns':-1},valid|{'coordinator_last_elapsed_ns':M.C.ORIGINAL_NS+1},
            valid|{'availability':'Unavailable'}]
        for k,v in (('phase','secret'),('owner','secret'),('subphase','secret'),('snapshot_count',True),
                    ('snapshot_count',0),('snapshot_count',M.C.MAX_RECORDS+1),('first_elapsed_ns',21),
                    ('first_elapsed_ns',-1),('last_elapsed_ns',21),('last_elapsed_ns',True),('private','secret')):
            bad.append(valid|{'last_phase':valid['last_phase']|{k:v}})
        for value in bad:
            out=io.StringIO()
            with contextlib.redirect_stdout(out),self.assertRaises(self.S.Failure):self.S.RuntimeRecords('external')(self.line(value))
            self.assertEqual(out.getvalue(),'')
    def test_broken_timing_output_does_not_replace_original_failure(self):
        records=self.S.RuntimeRecords('external');records(self.line(self.value()));emitted=[]
        def emit(kind,value):
            if kind=='OBSERVATION_TIMING_DIAGNOSTIC':raise BrokenPipeError('private unprinted exception')
            emitted.append((kind,value))
        with mock.patch.object(self.S,'emit',side_effect=emit):records(self.failed(M.C.EXTERNAL_PROFILE))
        self.assertEqual(records.finish(1)['code'],'deadline');self.assertEqual(emitted,[('FAILURE',self.S.P.failure('deadline'))])

if __name__=='__main__':unittest.main()



class InputDiagnosticProjectionTests(unittest.TestCase):
    def setUp(self):
        spec=importlib.util.spec_from_file_location('input_supervisor_tested',ROOT/'ci-financial-supervisor.py')
        self.S=importlib.util.module_from_spec(spec);spec.loader.exec_module(self.S)
    def value(self):return dict(version=1,budget=dict(site='idle_sweep',count=64,limit=64),last_main_loop=None)
    def line(self,v):return b'CI_FINANCIAL_INPUT_DIAGNOSTIC '+json.dumps(v,separators=(',',':')).encode()
    def test_failure_only_forwarding_and_duplicate_rejection(self):
        records=self.S.RuntimeRecords('external');out=io.StringIO()
        with contextlib.redirect_stdout(out):records(self.line(self.value()))
        self.assertEqual(out.getvalue(),'')
        with self.assertRaises(Exception):records(self.line(self.value()))
        with contextlib.redirect_stdout(out):records(b'CI_FINANCIAL_RESULT '+json.dumps(self.S.P.failure('input_budget')).encode())
        self.assertIn('CI_FINANCIAL_INPUT_DIAGNOSTIC ',out.getvalue())
    def test_wrong_failure_and_candidate_rejected(self):
        for result in [self.S.P.failure('input_phase'),dict(schema=1,profile=M.C.EXTERNAL_PROFILE,native_oracle_verified=True,fixture_cleaned=True,display_cleaned=True,public_chain_verified=False,dispatch_attempted=False)]:
            records=self.S.RuntimeRecords('external');records(self.line(self.value()))
            prefix=b'CI_FINANCIAL_RESULT ' if 'code' in result else b'CI_FINANCIAL_CANDIDATE '
            with self.assertRaises(Exception):records(prefix+json.dumps(result).encode())
    def test_emitter_uses_only_cached_state_and_preserves_unknown_error(self):
        error=M.C.Rejected('input_budget');error.input_budget=self.value()['budget']
        flow=mock.Mock(input_checkpoint=None);out=io.StringIO()
        with contextlib.redirect_stdout(out):M.emit_cached_input_failure(flow,error)
        self.assertEqual(json.loads(out.getvalue().split(' ',1)[1]),self.value());flow.assert_not_called()
        out=io.StringIO()
        with contextlib.redirect_stdout(out):M.emit_cached_input_failure(None,ValueError('private'))
        self.assertEqual(out.getvalue(),'')
    def test_diagnostic_output_failure_preserves_original_runtime_result(self):
        records=self.S.RuntimeRecords('external');records(self.line(self.value()))
        failure=self.S.P.failure('input_budget');seen=[]
        def emit(kind,value):
            if kind=='INPUT_DIAGNOSTIC':raise BrokenPipeError('private')
            seen.append((kind,value))
        with mock.patch.object(self.S,'emit',side_effect=emit):
            records(b'CI_FINANCIAL_RESULT '+json.dumps(failure).encode())
        self.assertEqual(records.first_failure,failure);self.assertEqual(records.result,failure)
        self.assertEqual(seen,[('FAILURE',failure)])
