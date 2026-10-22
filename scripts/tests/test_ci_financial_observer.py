import importlib.util
import json
import os
import pathlib
import sys
import tempfile
import time
import unittest
ROOT=pathlib.Path(__file__).resolve().parents[1]
spec=importlib.util.spec_from_file_location('financial_observer_tested',ROOT/'ci-financial-observer.py')
O=importlib.util.module_from_spec(spec);sys.modules[spec.name]=O;spec.loader.exec_module(O)

def observed_snapshot(**kwargs):
    kwargs.setdefault('host_observation',dict(revision=0,nonws_end=0,context_valid=True,
        entry='Writing' if kwargs.get('host_input') else 'Idle',editor=None,view=None))
    return kwargs

class CollectorTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.directory=pathlib.Path(self.temp.name)
        self.collector=O.ObserverFiles(self.directory,time.monotonic_ns()+1_000_000_000)
        self.record=dict(schema=1,profile=O.C.PROFILE,role='Coordinator',sequence=1,elapsed_ns=0,
                         kind='Birth',facts=dict(pid=100,parent_pid=99,parent_role=None))
    def tearDown(self):self.temp.cleanup()
    def write(self,data,name='100.jsonl',mode=0o600):
        p=self.directory/name;p.write_bytes(data);p.chmod(mode);return p
    def encoded(self):return json.dumps(self.record).encode()+b'\n'
    def test_actual_private_record(self):
        self.write(self.encoded());self.assertEqual(self.collector.read(),[self.record])
    def test_incomplete_suffix_waits_not_drops_at_final(self):
        p=self.write(self.encoded()+b'{');self.assertEqual(self.collector.read(),[self.record])
        with self.assertRaises(Exception):self.collector.read(final=True)
    def test_rewrite_rejected(self):
        p=self.write(self.encoded());self.collector.read();p.write_bytes(b'')
        with self.assertRaises(Exception):self.collector.read()
    def test_wrong_permission_rejected(self):
        self.write(self.encoded(),mode=0o644)
        with self.assertRaises(Exception):self.collector.read()
    def test_replaced_inode_rejected(self):
        p=self.write(self.encoded());self.collector.read()
        replacement=self.directory/'replacement';replacement.write_bytes(self.encoded());replacement.chmod(0o600)
        os.replace(replacement,p)
        with self.assertRaises(Exception):self.collector.read()
    def test_pid_filename_binding(self):
        self.write(self.encoded(),name='101.jsonl')
        with self.assertRaises(Exception):self.collector.read()
    def test_absent_roles_not_full_evidence(self):
        self.write(self.encoded())
        with self.assertRaises(Exception):self.collector.read(final=True)
    def test_symlink_rejected(self):
        target=self.directory/'target';target.write_bytes(self.encoded());target.chmod(0o600)
        (self.directory/'100.jsonl').symlink_to(target)
        with self.assertRaises(Exception):self.collector.read()


# Pure transport regression: native input ACKs are exercised without a socket,
# compositor, product process, pixels, fixture, or credentials.
spec=importlib.util.spec_from_file_location('financial_scroll_controller_tested',ROOT/'ci-financial-controller.py')
K=importlib.util.module_from_spec(spec);sys.modules[spec.name]=K;spec.loader.exec_module(K)

class NativeAckTransport:
    def __init__(self, mutate=None):
        self.commands=[];self.closed=False;self.mutate=mutate
    def settimeout(self, value):pass
    def send(self, packet, flags):
        command=K.COMMAND.unpack(packet);self.commands.append(command)
        sequence,op=command[2:4]
        # module.c's input handler sets input_sequence = sequence before ack().
        self.header=[K.MAGIC,K.VERSION,sequence,K.ACK,0,10+sequence,20+sequence,0,0,0,0,sequence]
        if self.mutate and op==K.SCROLL_UP:self.mutate(self.header)
        return len(packet)
    def recvmsg(self, size, ancillary_size, flags):
        return K.HEADER.pack(*self.header),[],0,None
    def close(self):self.closed=True

class NativeScrollAckTests(unittest.TestCase):
    def controller(self, mutate=None):
        transport=NativeAckTransport(mutate)
        controller=K.Controller(transport,1_000_000_000,1_000_000_000,_clock=lambda:1)
        controller._ready=controller._bound=True
        self.addCleanup(controller.close)
        return controller,transport
    def test_upward_scan_accepts_exact_native_input_ack_and_advances_barrier(self):
        controller,transport=self.controller()
        receipt=controller.scroll_up(100,200)
        self.assertEqual([c[3] for c in transport.commands],[K.MOVE,K.SCROLL_UP])
        self.assertEqual(receipt,K.Receipt(2,12,22,2))
        self.assertEqual(controller._last_input_commit,12)
        self.assertFalse(transport.closed)
    def test_downward_scan_keeps_same_input_ack_contract(self):
        controller,transport=self.controller()
        self.assertEqual(controller.scroll_down(100,200),K.Receipt(2,12,22,2))
        self.assertEqual(controller._last_input_commit,12)
    def test_upward_scan_rejects_stale_future_or_mismatched_ack(self):
        for field,value in ((11,1),(11,3),(2,1),(3,K.READY),(5,10),(6,20),(7,1)):
            with self.subTest(field=field,value=value):
                controller,transport=self.controller(lambda h:h.__setitem__(field,value))
                with self.assertRaises(K.Rejected) as error:controller.scroll_up(100,200)
                self.assertEqual(error.exception.code,'protocol')
                self.assertTrue(transport.closed)
                self.assertEqual(controller.receipt,K.Receipt(1,11,21,1))
                self.assertEqual(controller._last_input_commit,11)
    def test_non_input_ack_must_not_advance_input_sequence(self):
        controller,transport=self.controller()
        controller._sequence=2
        controller._receipt=K.Receipt(1,11,21,1)
        transport.header=[K.MAGIC,K.VERSION,2,K.ACK,0,12,22,0,0,0,0,1]
        self.assertEqual(controller._ack(K.PROGRESS),K.Receipt(2,12,22,1))
        transport.header[11]=2
        with self.assertRaises(K.Rejected):controller._ack(K.PROGRESS)
    def test_native_scroll_directions_share_sequence_advancing_handler(self):
        source=(ROOT/'ci-financial-weston-module.c').read_text()
        start=source.index('} else if ((op == SCROLL_DOWN || op == SCROLL_UP)')
        end=source.index('c->input_sequence = c->sequence;',start)
        self.assertIn('.value = op == SCROLL_UP ? -120.0 : 120.0',source[start:end])
        self.assertIn('(void)ack(c);',source[end:end+80])


# Pure scheduling regressions: no product, UI, credentials or forged runtime proof.
spec=importlib.util.spec_from_file_location('financial_completion_flow_tested',ROOT/'ci-financial-flow.py')
F=importlib.util.module_from_spec(spec);sys.modules[spec.name]=F;spec.loader.exec_module(F)

class CompletionSnapshotTests(unittest.TestCase):
    def flow(self, kinds, *, failure_after_snapshot=False, expired_after_snapshot=False):
        from unittest import mock
        profile=F.C.EXTERNAL_PROFILE
        def record(kind, sequence):
            return dict(schema=1,profile=profile,role='Coordinator',sequence=sequence,
                        elapsed_ns=sequence,kind=kind,facts={})
        proof=[record(kind,i+1) for i,kind in enumerate(kinds)]
        failure=record('Failure',len(proof)+1);failure['facts']={'code':'normal_finish'}
        class Observer:
            expected_profile=profile
            generation=0
            def read(self):
                if self.generation and expired_after_snapshot:raise F.C.Rejected('deadline')
                if not self.generation:return []
                return proof+([failure] if failure_after_snapshot else [])
            def next_snapshot(self, deadline):
                self.generation+=1
                return observed_snapshot(phase='Finished',subphase='None',owner=None,
                    view_generation=self.generation,focused=True,secret_input=False,
                    host_input=False,pixels_per_point=1,viewport=[1280,800],
                    host_observation=dict(revision=0,nonws_end=0,context_valid=True,entry='Idle',editor=None,view=None),
                    widgets=[dict(tag='Close',owner=None,rect=[10,10,30,30],enabled=True)])
        fixture=mock.Mock();fixture.deadline_ns=123
        controller=mock.Mock()
        return F.FullFlow(controller,fixture,Observer(),None),controller,proof
    def test_finished_snapshot_refreshes_records_before_unchanged_native_guard(self):
        flow,controller,proof=self.flow(('NormalFinishAdmitted','PtyHeld','PtyReleased','NormalFinished'))
        flow.run()
        self.assertEqual(flow.records,proof)
        controller.terminal_click.assert_called_once_with(20,20)
        controller.click.assert_not_called()
        # Actual stable-frame checks remain in place before the sole Close.
        self.assertEqual(flow.observer.generation,3)
    def test_cancel_missing_or_duplicate_normal_proof_never_closes(self):
        kinds=('NormalFinishAdmitted','PtyHeld','PtyReleased','NormalFinished')
        cases=[()]+[kinds[:i]+kinds[i+1:] for i in range(4)]+[kinds+(kind,) for kind in kinds]
        for case in cases:
            with self.subTest(kinds=case):
                flow,controller,_=self.flow(case)
                with self.assertRaises(F.C.Rejected) as error:flow.run()
                self.assertEqual(error.exception.code,'normal_finish')
                controller.terminal_click.assert_not_called()
                controller.click.assert_not_called()
    def test_failure_arriving_during_snapshot_is_not_ignored(self):
        flow,controller,_=self.flow(('NormalFinishAdmitted','PtyHeld','PtyReleased','NormalFinished'),failure_after_snapshot=True)
        with self.assertRaises(F.C.Rejected) as error:flow.run()
        self.assertEqual(error.exception.code,'observer_failure')
        controller.terminal_click.assert_not_called()
    def test_refresh_cannot_extend_original_observer_deadline(self):
        flow,controller,_=self.flow(('NormalFinishAdmitted','PtyHeld','PtyReleased','NormalFinished'),expired_after_snapshot=True)
        with self.assertRaises(F.C.Rejected) as error:flow.run()
        self.assertEqual(error.exception.code,'deadline')
        self.assertEqual(flow.fixture.deadline_ns,123)
        controller.terminal_click.assert_not_called()


class DeferredHostPromptTests(unittest.TestCase):
    PROMPTS=(('Exact coordinated reviewer selection JSON','reviewer_index'),
             ('Exact copied native continuation selector JSON file','continue_index'),
             ('Exact copied native AwaitingReturn result selector JSON file','result_index'))
    def setUp(self):
        from unittest import mock
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup)
        self.directory=pathlib.Path(self.temp.name)
        self.collector=O.ObserverFiles(self.directory,time.monotonic_ns()+10_000_000_000,F.C.EXTERNAL_PROFILE)
        self.path=self.directory/'100.jsonl'
        self.birth=dict(schema=1,profile=F.C.EXTERNAL_PROFILE,role='Host',sequence=1,
                        elapsed_ns=0,kind='Birth',facts=dict(pid=100,parent_pid=99,parent_role='Coordinator'))
        self.path.write_text(json.dumps(self.birth)+'\n');self.path.chmod(0o600)
        self.selection=self.directory.parent/(self.directory.name+'-selection')
        self.addCleanup(self.selection.unlink,missing_ok=True)
        self.fixture=mock.Mock()
        self.fixture.source.return_value={'original_capture':{'scope':{'participant_id':'synthetic'}},
                                          'entry_selection':{'account_id':'synthetic'}}
        self.fixture._data={'delivery_choices':{}}
        self.fixture.source_path.return_value=str(self.selection)
    def flow(self,index=1):
        from unittest import mock
        observer=mock.Mock();observer.expected_profile=F.C.EXTERNAL_PROFILE
        flow=F.FullFlow(mock.Mock(),self.fixture,observer,None)
        flow.records=self.collector.read()
        flow.startup_index=len(F.HOST_STARTUP) # this fixture starts after native startup
        flow.reviewer_index=flow.continue_index=flow.result_index=index
        return flow
    def append_ready(self):
        record=self.birth|dict(sequence=2,elapsed_ns=1,kind='HostMilestone',facts={'step':'Owner1SigningRetired'})
        with self.path.open('a') as stream:stream.write(json.dumps(record)+'\n')
    def test_identical_prompts_wait_for_observed_milestone_then_consume_only_once(self):
        flows=[(self.flow(),prompt,counter) for prompt,counter in self.PROMPTS]
        self.selection.write_text('{}')
        for flow,prompt,counter in flows:
            for _ in range(3):
                self.assertIsNone(flow.expected_host_line(prompt))
                self.assertEqual(getattr(flow,counter),1)
                self.assertEqual(flow.actions,0);self.assertEqual(flow.host_lines,0)
            flow.controller.click.assert_not_called()
        self.append_ready()
        for flow,prompt,counter in flows:
            with self.subTest(counter=counter):
                flow.records=self.collector.read() # real append-only collector update
                self.assertIsNotNone(flow.expected_host_line(prompt))
                self.assertEqual(getattr(flow,counter),2)
                for _ in range(3):self.assertIsNone(flow.expected_host_line(prompt))
                self.assertEqual(getattr(flow,counter),2)
                flow.controller.click.assert_not_called()
    def test_selector_still_waits_for_existing_file_after_milestone(self):
        self.append_ready()
        for prompt,counter in self.PROMPTS[1:]:
            with self.subTest(counter=counter):
                self.selection.unlink(missing_ok=True)
                flow=self.flow()
                for _ in range(3):self.assertIsNone(flow.expected_host_line(prompt))
                self.assertEqual(getattr(flow,counter),1)
                self.selection.write_text('{}')
                self.assertIsNotNone(flow.expected_host_line(prompt))
                self.assertEqual(getattr(flow,counter),2)
                self.fixture.source_path.assert_called_with('Signer2',
                    'continuation_output_file' if counter=='continue_index' else 'result_output_file',must_exist=True)
                self.assertIsNone(flow.expected_host_line(prompt))
    def test_terminal_counters_never_reopen_on_changed_or_identical_prompts(self):
        self.append_ready();self.selection.write_text('{}')
        for prompt,counter in self.PROMPTS:
            with self.subTest(counter=counter):
                flow=self.flow(index=2)
                for text in (prompt,prompt,prompt+' synthetic suffix'):
                    self.assertIsNone(flow.expected_host_line(text))
                self.assertEqual(getattr(flow,counter),2)
                self.assertEqual(flow.actions,0)
    def test_first_owner_does_not_require_second_owner_gate(self):
        self.selection.write_text('{}')
        for prompt,counter in self.PROMPTS:
            with self.subTest(counter=counter):
                flow=self.flow(index=0)
                self.assertIsNotNone(flow.expected_host_line(prompt))
                self.assertEqual(getattr(flow,counter),1)
                self.assertIsNone(flow.expected_host_line(prompt))
                self.assertEqual(getattr(flow,counter),1)


class FailureCheckpointTests(unittest.TestCase):
    def flow(self,phases,proof=False):
        kinds=('NormalFinishAdmitted','PtyHeld','PtyReleased','NormalFinished') if proof else ()
        flow,controller,_=CompletionSnapshotTests.flow(self,kinds)
        original=flow.native.next_snapshot;pending=list(phases)
        def next_snapshot(deadline):
            snapshot=original(deadline)
            if pending:
                phase,subphase,owner=pending.pop(0)
                snapshot.update(phase=phase,subphase=subphase,owner=owner)
            return snapshot
        flow.native.next_snapshot=next_snapshot
        flow.startup_index=len(F.HOST_STARTUP) # later-phase checkpoint test
        return flow,controller
    def test_terminal_first_omits_location_and_keeps_actual_failure_code(self):
        for phase,code in (('Revoked','source_failure'),('Finished','normal_finish')):
            with self.subTest(phase=phase):
                flow,controller=self.flow([(phase,'None',None)])
                with self.assertRaises(F.C.Rejected) as error:flow.run()
                self.assertEqual(error.exception.code,code)
                self.assertIsNone(flow.location)
                controller.terminal_click.assert_not_called()
    def test_actual_last_nonterminal_phase_subphase_owner_survives_terminal_failure(self):
        for phase,code in (('Revoked','source_failure'),('Finished','normal_finish')):
            with self.subTest(phase=phase):
                flow,controller=self.flow([('Waiting','None',None),('WriterFlow','Idle','Signer2'),(phase,'None',None)])
                with self.assertRaises(F.C.Rejected) as error:flow.run()
                self.assertEqual(error.exception.code,code)
                self.assertEqual(flow.location,{'phase':'WriterFlow','subphase':'Idle','owner':'Signer2'})
                controller.terminal_click.assert_not_called()
    def test_normal_success_keeps_proof_guard_and_emits_no_diagnostic(self):
        import contextlib,io
        for prefix,expected in (([],None),([('WriterFlow','Idle','Signer2')],
             {'phase':'WriterFlow','subphase':'Idle','owner':'Signer2'})):
            with self.subTest(prefix=prefix):
                flow,controller=self.flow(prefix+[('Finished','None',None)],proof=True)
                output=io.StringIO()
                with contextlib.redirect_stdout(output):flow.run()
                self.assertEqual(output.getvalue(),'')
                self.assertEqual(flow.location,expected)
                controller.terminal_click.assert_called_once_with(20,20)


class SyntheticStartupFixture(F.S.F.Fixture):
    def __init__(self,root):
        self.deadline_ns=123;self.secret_instances=[]
        self._fixture_root=root;self._artifact_root_identity=None
        profile=root/'profile';profile.mkdir(mode=0o700)
        self._data={'purpose':F.S.F.PURPOSE,'fixed_identity':{'agreement_id':'synthetic-agreement'},
                    'profile':str(profile),'workspace':str(root/'workspace'), 'sources':[]}
        for key in ('session_commands_file','delivery_choices_file','wallet_setup_file','host_password_file','source_password_file'):
            self._data[key]=str(root/F.S.F._HANDOFF_NAMES[key])
            path=pathlib.Path(self._data[key]);path.write_bytes(b'{}');path.chmod(0o600)
        for index in (1,2):
            self._data['sources'].append({'role':'signer'+str(index),'original_capture':{'scope':{
                'proposal':{'agreement_id':'synthetic-agreement'},
                'constructor':{'principal_id':'synthetic-roster-host'},
                'prover':{'principal_id':'synthetic-roster-host'}}}})
    def check(self):pass
    def preflight_input_budget(self):pass
    def secret(self,purpose):
        assert purpose=='host'
        secret=F.S.F.SyntheticSecret(F.S.F._TOKEN,F.S.F._SYNTHETIC_PASSWORDS['host'])
        self.secret_instances.append(secret);return secret

class HostStartupContractTests(unittest.TestCase):
    PROMPTS=(
        'Existing original Host profile directory (absolute): ',
        'Existing original dispatcher workspace directory (absolute): ',
        'Storage passphrase: ', 'Original primary financial passphrase: ',
        'Authenticate the same final-v4 original workspace. Type APPROVE 0123456789abcdef to approve this exact operation, or anything else to reject: ',
        'Local application principal ID: ',
        'Scope choice: type SELECTED for only exact agreement IDs (including any new IDs you intend to create), OWNED for all existing AND future agreements owned by this principal plus selected shared IDs, or ALL for every local agreement: ',
        'Additional shared agreement IDs, comma-separated; blank for none: ',
        'Grant READ only, or PREPARE (read/propose/intent/coordinate/disclose; never signing/submission)? ',
        'Optional exact browser origin for this session (for example http://127.0.0.1:4319); blank keeps native-app-only access: ',
        'New private bootstrap credential file (absolute path; manually enter it only in the approved local application): ',
        'Grant this session until lock/restart/revoke. Type APPROVE fedcba9876543210 to approve this exact operation, or anything else to reject: ',
        'Exact immutable command keys JSON file {version:1,bind_key,intake_keys:[first,second],completion_key} (absolute): ')
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup)
        from unittest import mock
        parent=pathlib.Path(self.temp.name);self.root=parent/'f-synthetic';self.root.mkdir(mode=0o700)
        patch=mock.patch.object(F.S.F,'ARTIFACT_PARENT',parent);patch.start();self.addCleanup(patch.stop)
        self.fixture=SyntheticStartupFixture(self.root)
    def flow(self):
        from unittest import mock
        observer=mock.Mock();observer.expected_profile=F.C.EXTERNAL_PROFILE
        return F.FullFlow(mock.Mock(),self.fixture,observer,None)
    def acknowledge(self,flow):
        flow.pending_startup=flow.startup_index;flow.startup_submitted();flow.startup_waiting=False
    def test_whole_real_prompt_sequence_has_exact_read_only_responses_and_separate_latches(self):
        flow=self.flow();actual=[]
        for index,prompt in enumerate(self.PROMPTS):
            text='\n'.join(self.PROMPTS[:index+1]);line=flow.expected_host_line(text)
            self.assertIsNotNone(line);actual.append(line)
            self.assertEqual(flow.startup_index,index)
            self.assertIsNone(flow.expected_host_line(text))
            self.assertIsNone(flow.expected_host_line('changed old display '+text))
            self.acknowledge(flow)
        self.assertEqual(actual,[('public',self.fixture._data['profile']),('public',self.fixture._data['workspace']),
            ('secret',None),('secret',None),('public','APPROVE 0123456789abcdef'),
            ('public','synthetic-roster-host'),('public','OWNED'),('public',''),('public','READ'),('public',''),
            ('public',str(self.root/'coordinated-host-runtime-session.token')),
            ('public','APPROVE fedcba9876543210'),('public',self.fixture._data['session_commands_file'])])
        self.assertEqual(flow.startup_index,13)
    def test_skipped_or_future_gate_never_issues_input(self):
        for future in range(1,len(self.PROMPTS)):
            with self.subTest(future=future):
                flow=self.flow()
                with self.assertRaises((F.C.Rejected,F.S.F.C.Rejected)):flow.expected_host_line(self.PROMPTS[future])
                self.assertIsNone(flow.startup_issued);flow.controller.click.assert_not_called()
    def test_earlier_changed_prompts_never_reopen(self):
        flow=self.flow()
        for index,prompt in enumerate(self.PROMPTS):
            self.assertIsNotNone(flow.expected_host_line(prompt));self.acknowledge(flow)
            if index<12:
                for old in self.PROMPTS[:index+1]:self.assertIsNone(flow.expected_host_line('stale '+old))
    def test_selected_scope_alternative_rejected_not_silently_granted(self):
        flow=self.flow()
        for prompt in self.PROMPTS[:7]:flow.expected_host_line(prompt);self.acknowledge(flow)
        with self.assertRaises((F.C.Rejected,F.S.F.C.Rejected)):flow.expected_host_line('Exact selected agreement IDs, comma-separated; blank grants no agreements: ')
    def test_malformed_challenge_does_not_advance_or_invent_response(self):
        for value in ('0123456789abcdeg','0123456789ABCDEF','0123456789abcde'):
            flow=self.flow()
            for prompt in self.PROMPTS[:4]:flow.expected_host_line(prompt);self.acknowledge(flow)
            self.assertIsNone(flow.expected_host_line(self.PROMPTS[4].replace('0123456789abcdef',value)))
            self.assertEqual(flow.startup_index,4);self.assertIsNone(flow.startup_issued)
    def test_submit_cannot_advance_unissued_prompt(self):
        flow=self.flow()
        with self.assertRaises((F.C.Rejected,F.S.F.C.Rejected)):flow.startup_submitted()
        self.assertEqual(flow.startup_index,0)
    def test_each_preserved_identity_and_agreement_is_required(self):
        import copy
        original=copy.deepcopy(self.fixture._data)
        for source in range(2):
            for role in ('constructor','prover'):
                for replacement in ({},{'principal_id':'other'}):
                    self.fixture._data=copy.deepcopy(original)
                    self.fixture._data['sources'][source]['original_capture']['scope'][role]=replacement
                    flow=self.flow()
                    with self.assertRaises((F.C.Rejected,F.S.F.C.Rejected)):flow.expected_host_line(self.PROMPTS[0])
                    self.assertIsNone(flow.startup_issued);flow.controller.click.assert_not_called()
            self.fixture._data=copy.deepcopy(original)
            self.fixture._data['sources'][source]['original_capture']['scope']['proposal']['agreement_id']='other'
            with self.assertRaises((F.C.Rejected,F.S.F.C.Rejected)):self.fixture.validate_host_startup()
        self.fixture._data=original;self.fixture._data['purpose']='unrecognized'
        with self.assertRaises((F.C.Rejected,F.S.F.C.Rejected)):self.fixture.validate_host_startup()
    def test_native_only_credential_destination_is_absent_outside_profile_and_uncreated(self):
        path=pathlib.Path(self.fixture.host_credential_destination())
        self.assertEqual(path.parent,self.root);self.assertFalse(path.exists())
        self.assertFalse(path.is_relative_to(self.fixture._data['profile']))
    def test_credential_collision_symlink_wrong_root_and_profile_alias_fail_without_reading(self):
        from unittest import mock
        target=self.root/'coordinated-host-runtime-session.token'
        for form in ('regular','symlink','directory'):
            if form=='regular':target.write_text('synthetic token must not be read')
            elif form=='symlink':target.symlink_to(self.root/'absent')
            else:target.mkdir()
            with mock.patch.object(pathlib.Path,'read_bytes',side_effect=AssertionError('token read forbidden')):
                with self.assertRaises((F.C.Rejected,F.S.F.C.Rejected)):self.fixture.host_credential_destination()
            if form=='directory':target.rmdir()
            else:target.unlink()
        old=self.fixture._data['host_password_file'];self.fixture._data['host_password_file']=str(self.root.parent/'elsewhere'/'password')
        with self.assertRaises((F.C.Rejected,F.S.F.C.Rejected)):self.fixture.host_credential_destination()
        self.fixture._data['host_password_file']=old
        self.fixture._data['profile']=str(self.root)
        with self.assertRaises((F.C.Rejected,F.S.F.C.Rejected)):self.fixture.host_credential_destination()
    def test_credential_root_symlink_or_nonprivate_mode_rejected(self):
        self.root.chmod(0o755)
        with self.assertRaises((F.C.Rejected,F.S.F.C.Rejected)):self.fixture.host_credential_destination()
        self.root.chmod(0o700)
        link=self.root/'alias';link.symlink_to(self.root,target_is_directory=True)
        for key in ('session_commands_file','delivery_choices_file','wallet_setup_file','host_password_file','source_password_file'):
            self.fixture._data[key]=str(link/key)
        with self.assertRaises((F.C.Rejected,F.S.F.C.Rejected)):self.fixture.host_credential_destination()
    def test_uncertain_submit_never_retypes_or_advances_startup(self):
        from unittest import mock
        flow=self.flow();flow.pending_host=flow.expected_host_line(self.PROMPTS[0]);flow.pending_startup=0
        flow.native.public_host_line=mock.Mock()
        flow.host_lines=1;flow.pending_occurrence=(0,F.H.count(self.PROMPTS[0]),1)
        snapshot=observed_snapshot(phase='Selecting',owner=None,host_input=True,secret_input=False,
            host_observation=dict(revision=1,nonws_end=flow.pending_occurrence[1],context_valid=True,
                                  entry='Editing',editor=dict(ordinal=1,revision=1),view=None))
        flow.snapshot=mock.Mock(return_value=snapshot)
        flow.press=mock.Mock(side_effect=F.C.Rejected('process'))
        with self.assertRaises(F.C.Rejected):flow.pump_host(snapshot)
        self.assertEqual(flow.startup_index,0)
        with self.assertRaises(F.C.Rejected) as error:flow.pump_host(snapshot)
        self.assertEqual(error.exception.code,'replay')
        flow.native.public_host_line.assert_called_once();flow.press.assert_called_once()
    def test_transitive_native_prompt_order_and_synthetic_read_only_precedent(self):
        host=ROOT.parent/'crates/wholepact-native-host/src'
        dispatcher=(host/'host/durable_dispatcher_v2.rs').read_text()
        registered=dispatcher[dispatcher.index('fn open_workspace_dispatcher_registered_v4('):dispatcher.index('struct InitialAdmissionInspection')]
        order=['Storage passphrase: ','Original primary financial passphrase: ','terminal.approve_historical(',
               'host.enroll()?;','host.require_private_workspace_read_session_v1()?;']
        self.assertEqual([registered.index(x) for x in order],sorted(registered.index(x) for x in order))
        enrollment=(host/'host.rs').read_text()
        for index in (5,6,7,8,9,10):self.assertIn(self.PROMPTS[index],enrollment)
        source=next(host.rglob('private_fixed_v2.rs')).read_text()
        precedent=source[source.index('pub(super) fn session_inputs'):source.index('fn open_inputs')]
        for value in ('"synthetic-roster-host"','"OWNED"','if read_only { "READ" }','Input::CapturedPath'):
            self.assertIn(value,precedent)
    def test_credential_wrong_owner_and_symlink_profile_rejected(self):
        from unittest import mock
        with mock.patch.object(F.S.F.os,'getuid',return_value=os.getuid()+1):
            with self.assertRaises(F.S.F.C.Rejected):self.fixture.host_credential_destination()
        link=self.root/'profile-alias';link.symlink_to(self.root/'profile',target_is_directory=True)
        self.fixture._data['profile']=str(link)
        with self.assertRaises(F.S.F.C.Rejected):self.fixture.host_credential_destination()
    def test_loaded_handoff_binds_root_and_wrong_filename_or_sibling_fails(self):
        class Loaded(F.S.F.Fixture):
            def __init__(self,data,*args):
                self._data=data;self._fixture_root=None;self._artifact_root_identity=None
        descriptor=self.root/F.S.F.FIXTURE_FILE
        descriptor.write_text(json.dumps(self.fixture._data));descriptor.chmod(0o600)
        loaded=Loaded.load(descriptor,123)
        self.assertEqual(loaded._fixture_root,self.root)
        self.assertEqual(loaded._artifact_root_identity,(self.root.stat().st_dev,self.root.stat().st_ino))
        with self.assertRaises(F.S.F.C.Rejected):Loaded.load(self.root/'wrong-name.json',123)
        sibling=self.root.parent/'f-sibling';sibling.mkdir(mode=0o700)
        wrong=sibling/F.S.F.FIXTURE_FILE;wrong.write_text(json.dumps(self.fixture._data));wrong.chmod(0o600)
        with self.assertRaises(F.S.F.C.Rejected):Loaded.load(wrong,123)
    def test_unbound_root_handoff_alias_and_root_replacement_are_rejected(self):
        self.fixture._fixture_root=None
        with self.assertRaises(F.S.F.C.Rejected):self.fixture.host_credential_destination()
        self.fixture._fixture_root=self.root
        old=self.fixture._data['session_commands_file'];self.fixture._data['session_commands_file']=str(self.root/'other.json')
        with self.assertRaises(F.S.F.C.Rejected):self.fixture.host_credential_destination()
        self.fixture._data['session_commands_file']=old
        self.fixture.host_credential_destination() # pin exact directory identity
        renamed=self.root.parent/'f-retained-old';self.root.rename(renamed);self.root.mkdir(mode=0o700)
        for name in F.S.F._HANDOFF_NAMES.values():
            p=self.root/name;p.write_bytes(b'{}');p.chmod(0o600)
        (self.root/'profile').mkdir(mode=0o700)
        with self.assertRaises(F.S.F.C.Rejected):self.fixture.host_credential_destination()
    def test_handoff_symlink_or_hardlink_never_counts_as_private_original(self):
        target=pathlib.Path(self.fixture._data['host_password_file']);target.unlink()
        other=pathlib.Path(self.fixture._data['source_password_file'])
        target.symlink_to(other)
        with self.assertRaises(F.S.F.C.Rejected):self.fixture.host_credential_destination()
        target.unlink();os.link(other,target)
        with self.assertRaises(F.S.F.C.Rejected):self.fixture.host_credential_destination()
    def test_full_run_owned_writing_is_observation_only_until_later_idle(self):
        from unittest import mock
        flow=self.flow();flow.startup_index=13;flow.startup_waiting=True;flow.startup_focus_seen=True
        base=observed_snapshot(phase='Selecting',subphase='None',owner=None,focused=True,secret_input=False,widgets=[])
        flow.snapshot=mock.Mock(side_effect=[base|{'host_input':True},base|{'host_input':True},base|{'host_input':False}])
        def source_action(*args):
            self.assertTrue(flow.host_startup_complete)
            raise F.C.Rejected('missing_evidence') # pure test stop after scheduling boundary
        flow.save_selector=mock.Mock(side_effect=source_action)
        flow.idle_scan=mock.Mock(side_effect=AssertionError('no source scroll during Writing'))
        self.assertFalse(flow.host_startup_complete)
        with self.assertRaises(F.C.Rejected) as error:flow.run()
        self.assertEqual(error.exception.code,'missing_evidence')
        self.assertEqual(flow.controller.wait_render_progress.call_count,2)
        flow.controller.click.assert_not_called();flow.controller.scroll_down.assert_not_called()
        flow.controller.scroll_up.assert_not_called();flow.save_selector.assert_called_once()
    def test_command_reply_preparation_and_submission_do_not_finish_until_idle(self):
        from unittest import mock
        flow=self.flow()
        for prompt in self.PROMPTS[:12]:flow.expected_host_line(prompt);self.acknowledge(flow)
        reply=flow.expected_host_line(self.PROMPTS[12]);self.assertFalse(flow.host_startup_complete)
        flow.pending_host=reply;flow.pending_startup=12
        flow.startup_submitted();flow.pending_host=None
        self.assertFalse(flow.host_startup_complete)
        flow.pump_host(observed_snapshot(secret_input=False,host_input=True));self.assertFalse(flow.host_startup_complete)
        flow.pump_host(observed_snapshot(secret_input=False,host_input=False));self.assertTrue(flow.host_startup_complete)
    def test_actual_native_methods_focus_type_blank_and_submit_once_with_writing_wait(self):
        from unittest import mock
        import itertools,contextlib,io
        from test_ci_financial_input_batching import RecordingController,raw_event_count
        controller=mock.Mock();budget=RecordingController()
        state=dict(mode='Idle',remaining=0,step=0,generation=0,line=None,submitted=[],captures=0,focus=0,
                   begin_boundary=0,submit_boundary=0,coverage=0)
        prompts=self.PROMPTS
        def text():return '\n'.join(prompts[:min(state['step']+1,13)])
        def crop():return (':' if state['coverage']==0 else 'directory (absolute): ') if state['step']==0 and state['coverage']<2 else text()
        class Observer:
            expected_profile=F.C.EXTERNAL_PROFILE
            def read(self):return []
            def next_snapshot(self,deadline):
                state['generation']+=1;assert state['generation']<5000,'finite synthetic frame bound'
                mode=state['mode']
                if mode in ('BeginIdle','SubmitEditing','Writing'):
                    if state['remaining']==0:
                        if mode=='BeginIdle':state['mode']='Editing'
                        elif mode=='SubmitEditing':state.update(mode='Writing',remaining=100)
                        else:state.update(mode='Idle',step=state['step']+1)
                        mode=state['mode']
                    else:state['remaining']-=1
                protected=mode!='Idle';editing=mode in ('Editing','SubmitEditing')
                entry='Editing' if editing else ('Writing' if mode=='Writing' else 'Idle')
                if mode=='BeginIdle':state['begin_boundary']+=1
                if mode=='SubmitEditing':state['submit_boundary']+=1
                widgets=[('HostEditor',100),('HostSubmit',150)] if editing else ([('HostOutput',200),('BeginHostLine',250),('ScrollRegion',400)] if not protected else [])
                h=dict(revision=min(state['step']+1,13),nonws_end=F.H.count(text()),context_valid=True,
                       entry=entry,editor=dict(ordinal=state['step']+1,revision=state['step']+1) if editing else None,
                       view=dict(rect=[10,200,110,220],nonws=F.H.count(crop()),rows=20) if not protected else None)
                return observed_snapshot(phase='Selecting',owner=None,subphase='None',focused=True,
                    view_generation=state['generation'],secret_input=False,host_input=protected,host_observation=h,
                    pixels_per_point=1,viewport=[1280,800],widgets=[dict(tag=t,owner=None,rect=[10,y,110,y+20],enabled=True) for t,y in widgets])
        def click(x,y):
            if y==260:
                self.assertEqual(state['mode'],'Idle');state.update(mode='BeginIdle',remaining=2,line=None)
            elif y==110:
                self.assertEqual(state['mode'],'Editing');state['focus']+=1
            elif y==160:
                self.assertEqual(state['mode'],'Editing');self.assertIsNotNone(state['line'])
                state['submitted'].append(state['line']);state.update(mode='SubmitEditing',remaining=2)
            else:raise AssertionError('unexpected native action')
        def type_ascii(value):
            self.assertEqual(state['mode'],'Editing');budget.type_ascii(value);state['line']=('public',value)
        def key(op,a,b):
            self.assertEqual(state['mode'],'Editing');budget._command(op,a,b);state['line']=('secret',None)
        controller.click.side_effect=click;controller.type_ascii.side_effect=type_ascii;controller._command.side_effect=key
        controller._preflight_ascii_batches.side_effect=budget._preflight_ascii_batches
        controller.wait_render_progress.side_effect=budget.wait_render_progress
        @contextlib.contextmanager
        def observe():
            self.assertEqual(state['mode'],'Idle');state['captures']+=1;yield object()
        controller.observe.side_effect=observe
        def wheel(*args):
            self.assertEqual(state['mode'],'Idle');state['coverage']+=1
        controller.scroll_up.side_effect=wheel;controller.scroll_down.side_effect=wheel
        ocr=mock.Mock();ocr.read.side_effect=lambda *a:crop()
        flow=F.FullFlow(controller,self.fixture,Observer(),ocr)
        clock=itertools.count(10_000_000_000,2_000_000_000);output=io.StringIO()
        def first_source_action(*args):
            self.assertTrue(flow.host_startup_complete);self.assertEqual(state['mode'],'Idle')
            raise F.C.Rejected('missing_evidence') # intended pure-test stop after startup
        flow.save_selector=mock.Mock(side_effect=first_source_action)
        flow.idle_scan=mock.Mock(side_effect=AssertionError('no Source scan during Host startup'))
        with mock.patch.object(F.time,'monotonic_ns',side_effect=lambda:next(clock)),contextlib.redirect_stdout(output):
            with self.assertRaises(F.C.Rejected) as error:flow.run()
            self.assertEqual(error.exception.code,'missing_evidence')
        flow.save_selector.assert_called_once();flow.idle_scan.assert_not_called()
        self.assertEqual(output.getvalue(),'');self.assertEqual(len(state['submitted']),13)
        self.assertEqual(state['focus'],13);self.assertEqual(flow.actions,26)
        self.assertEqual(state['submitted'][7],('public',''));self.assertEqual(state['submitted'][9],('public',''))
        self.assertEqual(controller.type_ascii.call_args_list.count(mock.call('')),2)
        self.assertEqual(len(self.fixture.secret_instances),2)
        self.assertIsNot(self.fixture.secret_instances[0],self.fixture.secret_instances[1])
        self.assertTrue(all(not any(secret._bytes) for secret in self.fixture.secret_instances))
        self.assertEqual(state['captures'],15);controller.focus.assert_not_called()
        self.assertEqual(state['coverage'],2);self.assertEqual(controller.scroll_up.call_count,2)
        self.assertGreaterEqual(state['begin_boundary'],13);self.assertGreaterEqual(state['submit_boundary'],13)
        self.assertEqual(flow.host_occurrences.attempts,13)
        self.assertTrue(all(raw_event_count(batch)+3<=256 for batch in budget.batches))
        self.assertFalse(budget.held);self.assertFalse(budget.pending)

class BoundedIdleSweepTests(unittest.TestCase):
    def model(self, target_at=2400, enabled=True):
        from unittest import mock
        # Legal clipped layout: an untagged content gap fills the viewport.
        # The viewport's observed ScrollRegion stays fixed while content moves.
        state={'offset':200,'generation':0,'directions':[]}
        controller=mock.Mock()
        def wheel(direction):
            state['directions'].append(direction)
            state['offset']=max(0,min(10000,state['offset']+(120 if direction=='down' else -120)))
        controller.scroll_up.side_effect=lambda *args:wheel('up')
        controller.scroll_down.side_effect=lambda *args:wheel('down')
        class Observer:
            expected_profile=F.C.EXTERNAL_PROFILE
            def read(self):return []
            def next_snapshot(self,deadline):
                state['generation']+=1
                widgets=[dict(tag='ScrollRegion',owner=None,rect=[0,0,1280,800],enabled=True)]
                if state['offset']>=target_at:
                    widgets.append(dict(tag='ConfigureV3',owner='Signer1',rect=[20,600,200,630],enabled=enabled))
                return observed_snapshot(phase='Selecting',subphase='None',owner=None,
                    view_generation=state['generation'],focused=True,secret_input=False,
                    host_input=False,pixels_per_point=1,viewport=[1280,800],widgets=widgets)
        fixture=mock.Mock();fixture.deadline_ns=123
        return F.FullFlow(controller,fixture,Observer(),None),controller,state
    def test_sweep_crosses_unchanged_tag_geometry_and_clicks_only_real_enabled_target(self):
        flow,controller,state=self.model()
        for _ in range(64):
            s=flow.snapshot();w=flow.find(s,'ConfigureV3','Signer1')
            if w and w['enabled']:
                flow.press(s,'ConfigureV3','Signer1');break
            controller.click.assert_not_called()
            flow.idle_scan(s)
        else:self.fail('unchanged clipped geometry trapped target discovery')
        self.assertEqual(state['directions'],['up']*8+['down']*20)
        controller.click.assert_called_once_with(110,615)
        self.assertEqual(flow.actions,1)
        with self.assertRaises(F.C.Rejected):flow.press(s,'ConfigureV3','Signer1')
        self.assertEqual(controller.click.call_count,1)
    def test_absent_or_disabled_target_has_finite_budget_and_no_click(self):
        for options in ({'target_at':20000},{'target_at':0,'enabled':False}):
            with self.subTest(options=options):
                flow,controller,state=self.model(**options)
                for _ in range(64):flow.idle_scan(flow.snapshot())
                with self.assertRaises(F.C.Rejected) as error:flow.idle_scan(flow.snapshot())
                self.assertEqual(error.exception.code,'input_budget')
                self.assertEqual(state['directions'],['up']*8+['down']*56)
                controller.click.assert_not_called()
                controller.focus.assert_not_called();controller.type_ascii.assert_not_called()
                self.assertEqual(flow.fixture.deadline_ns,123)
    def test_missing_scroll_region_does_not_invent_coordinates_or_reset_budget(self):
        flow,controller,state=self.model();s=flow.snapshot();s['widgets']=[]
        for _ in range(64):self.assertFalse(flow.idle_scan(s))
        with self.assertRaises(F.C.Rejected):flow.idle_scan(s)
        controller.scroll_up.assert_not_called();controller.scroll_down.assert_not_called()
    def test_existing_scroll_limit_remains_enforced(self):
        flow,controller,state=self.model();s=flow.snapshot()
        flow.scrolls[('Selecting','None','ScrollRegion',None,'up')]=128
        with self.assertRaises(F.C.Rejected) as error:flow.idle_scan(s)
        self.assertEqual(error.exception.code,'input_budget')
        controller.scroll_up.assert_not_called()


class FullFlowStartupFocusTests(unittest.TestCase):
    def flow(self, snapshots):
        from unittest import mock
        flow,controller,state=BoundedIdleSweepTests.model(self,target_at=20000)
        original=flow.native.next_snapshot;pending=iter(snapshots)
        def snapshot(deadline):
            result=original(deadline);result.update(next(pending));return result
        flow.native.next_snapshot=snapshot
        flow.startup_index=len(F.HOST_STARTUP) # these tests isolate post-startup source sweep
        flow.pump_host=mock.Mock(return_value=False)
        flow.save_selector=mock.Mock(return_value=False)
        return flow,controller,state
    def test_delayed_startup_focus_observes_before_any_wheel_or_host_work(self):
        flow,controller,state=self.flow([{'focused':False}]*3+[{'focused':True},{'phase':'Revoked'}])
        with self.assertRaises(F.C.Rejected) as error:flow.run()
        self.assertEqual(error.exception.code,'source_failure')
        self.assertEqual([c[0] for c in controller.mock_calls[:3]],['wait_render_progress']*3)
        self.assertEqual(controller.scroll_up.call_count,1)
        self.assertEqual(flow.pump_host.call_count,1)
        controller.click.assert_not_called();controller.focus.assert_not_called()
    def test_never_focused_fails_within_64_observations_without_input(self):
        flow,controller,state=self.flow([{'focused':False}]*64)
        with self.assertRaises(F.C.Rejected) as error:flow.run()
        self.assertEqual(error.exception.code,'input_budget')
        self.assertEqual(state['generation'],64)
        self.assertEqual([c[0] for c in controller.mock_calls],['wait_render_progress']*63)
        flow.pump_host.assert_not_called();flow.fixture.secret.assert_not_called()
        self.assertEqual(flow.fixture.deadline_ns,123)
    def test_later_focus_loss_is_rejected_not_refocused(self):
        flow,controller,state=self.flow([{'focused':True},{'focused':False}])
        with self.assertRaises(F.C.Rejected) as error:flow.run()
        self.assertEqual(error.exception.code,'input_phase')
        self.assertEqual(controller.scroll_up.call_count,1)
        self.assertEqual(controller.wait_render_progress.call_count,1)
        controller.focus.assert_not_called()
    def test_unfocused_protected_or_wrong_startup_state_never_waits(self):
        for change in ({'host_input':True},{'secret_input':True},{'owner':'Signer1'},
                       {'subphase':'Idle'},{'phase':'Waiting'}):
            with self.subTest(change=change):
                flow,controller,state=self.flow([dict(focused=False,**change)])
                with self.assertRaises(F.C.Rejected) as error:flow.run()
                self.assertEqual(error.exception.code,'input_phase')
                self.assertEqual(controller.mock_calls,[])
                flow.pump_host.assert_not_called()
    def test_unfocused_terminal_handling_preserves_original_failure_and_proof_guard(self):
        for phase,code in (('Revoked','source_failure'),('Finished','normal_finish')):
            with self.subTest(phase=phase):
                flow,controller,state=self.flow([dict(focused=False,phase=phase)])
                with self.assertRaises(F.C.Rejected) as error:flow.run()
                self.assertEqual(error.exception.code,code)
                self.assertEqual(controller.mock_calls,[])
                flow.pump_host.assert_not_called()
                self.assertIsNone(flow.location)


if __name__=='__main__':unittest.main()




class PairedAdmissionTests(unittest.TestCase):
    def test_both_native_review_sides_precede_either_arm_for_each_owner(self):
        from unittest import mock
        native=(ROOT.parent/'crates/wholepact-financial-coordinator/src/financial_source_ui.rs').read_text()
        self.assertIn('consent.read == [true; 2] && consent.acknowledged == [true; 2]',native)
        self.assertIn('both && !self.signer_arm_sent',native)
        self.assertIn('both && !self.witness_arm_sent',native)
        for owner in ('Signer1','Signer2'):
            with self.subTest(owner=owner):
                flow=F.FullFlow(mock.Mock(),mock.Mock(),mock.Mock(),None)
                flow.startup_index=len(F.HOST_STARTUP) # paired admission is post-startup
                flow.pump_host=lambda s:False
                ack=[False,False];reads=[0,0];events=[];frames=[0]
                arms=('ArmSigner','ArmWitness');acks=('SignerReviewAcknowledgement','WitnessReviewAcknowledgement')
                bodies=('SignerReviewBody','WitnessReviewBody')
                class End(Exception):pass
                def snapshot():
                    frames[0]+=1
                    if frames[0]>24 or all(x in events for x in arms):raise End()
                    enabled=all(ack) and reads[0]>=2 and reads[1]>=3
                    return observed_snapshot(phase='AdmissionReview',subphase='None',owner=owner,focused=True,secret_input=False,host_input=False,
                        widgets=[dict(tag=t,owner=owner,enabled=enabled if t in arms else True) for t in (*acks,*bodies,*arms)])
                def press(s,tag,role,**kw):
                    self.assertEqual(role,owner)
                    if tag in arms:self.assertTrue(all(ack) and reads[0]>=2 and reads[1]>=3,'no early arm')
                    else:ack[acks.index(tag)]=True
                    self.assertNotIn(tag,events);events.append(tag)
                    flow.done.add(flow.key(s,tag,role)+(None,))
                def scroll(s,body,role,*args):
                    self.assertEqual(role,owner);reads[bodies.index(body)]+=1;events.append(body);return True
                flow.snapshot=snapshot;flow.press=press;flow.scroll=scroll
                with self.assertRaises(End):flow.run()
                self.assertEqual(events,[*acks,bodies[0],bodies[1],bodies[0],bodies[1],bodies[0],bodies[1],*arms])

    def test_missing_wrong_owner_ack_is_sought_not_armed(self):
        from unittest import mock
        flow=F.FullFlow(mock.Mock(),mock.Mock(),mock.Mock(),None)
        s=observed_snapshot(phase='AdmissionReview',subphase='None',owner='Signer1',widgets=[
            dict(tag='SignerReviewAcknowledgement',owner='Signer2',enabled=True)])
        flow.seek=mock.Mock();flow.press=mock.Mock();flow.scroll=mock.Mock()
        flow.paired_admission(s,'Signer1')
        flow.seek.assert_called_once_with(s,'SignerReviewAcknowledgement','Signer1')
        flow.press.assert_not_called();flow.scroll.assert_not_called()
    def test_disabled_arm_never_sent_and_review_bound_not_renewed(self):
        from unittest import mock
        flow=F.FullFlow(mock.Mock(),mock.Mock(),mock.Mock(),None)
        owner='Signer2';s=observed_snapshot(phase='AdmissionReview',subphase='None',owner=owner,
            widgets=[dict(tag=t,owner=owner,enabled=False) for t in ('ArmSigner','ArmWitness')])
        for tag in ('SignerReviewAcknowledgement','WitnessReviewAcknowledgement'):
            flow.done.add(flow.key(s,tag,owner)+(None,))
        flow.scrolls[('AdmissionReview','None','paired-review',owner)]=256
        flow.press=mock.Mock();flow.scroll=mock.Mock()
        with self.assertRaises(F.C.Rejected):flow.paired_admission(s,owner)
        flow.press.assert_not_called();flow.scroll.assert_not_called()
    def test_consumed_arms_not_repeated(self):
        from unittest import mock
        flow=F.FullFlow(mock.Mock(),mock.Mock(),mock.Mock(),None)
        owner='Signer1';s=observed_snapshot(phase='AdmissionReview',subphase='None',owner=owner,widgets=[])
        for tag in ('SignerReviewAcknowledgement','WitnessReviewAcknowledgement','ArmSigner','ArmWitness'):
            flow.done.add(flow.key(s,tag,owner)+(None,))
        flow.press=mock.Mock();flow.scroll=mock.Mock();flow.seek=mock.Mock()
        flow.paired_admission(s,owner)
        flow.press.assert_not_called();flow.scroll.assert_not_called();flow.seek.assert_not_called()

    def test_disjoint_arm_and_body_crops_complete_pending_scroll_before_reseeking_arm(self):
        from unittest import mock
        flow=F.FullFlow(mock.Mock(),mock.Mock(),mock.Mock(),None)
        owner='Signer1';view=['arm'];reads=[0,0];events=[]
        bodies=('SignerReviewBody','WitnessReviewBody');arms=('ArmSigner','ArmWitness')
        base=observed_snapshot(phase='AdmissionReview',subphase='None',owner=owner)
        for tag in ('SignerReviewAcknowledgement','WitnessReviewAcknowledgement'):
            flow.done.add(flow.key(base,tag,owner)+(None,))
        def seek(s,tag,role):view[0]='arm' if tag in arms else tag;events.append('seek:'+tag);return False
        def scroll(s,body,role):
            if view[0]!=body:return False
            reads[bodies.index(body)]+=1;events.append('scroll:'+body);return True
        def press(s,tag,role):
            self.assertTrue(all(reads));events.append(tag);flow.done.add(flow.key(s,tag,role)+(None,))
        flow.seek=seek;flow.scroll=scroll;flow.press=press
        for _ in range(20):
            widgets=([dict(tag=t,owner=owner,enabled=all(reads)) for t in arms] if view[0]=='arm' else
                     [dict(tag=view[0],owner=owner,enabled=True)])
            flow.paired_admission(base|dict(widgets=widgets),owner)
        self.assertEqual([e for e in events if e in arms],list(arms))
        self.assertEqual(reads,[1,1])

class ReviewViewportTests(unittest.TestCase):
    def test_actual_body_scroll_completes_between_disjoint_action_crops(self):
        from unittest import mock
        for ack in ('ReviewAcknowledgement',None):
            with self.subTest(ack=ack):
                flow=F.FullFlow(mock.Mock(),mock.Mock(),mock.Mock(),None)
                owner='Signer1';view=['action'];reads=[0];events=[]
                base=observed_snapshot(phase='ReturnReadReview',subphase='None',owner=owner,secret_input=False,host_input=False)
                if ack:flow.done.add(flow.key(base,ack,owner)+(None,))
                def seek(s,tag,role):view[0]='action' if tag=='ReturnRead' else 'body';events.append('seek:'+tag);return False
                def scroll(s,body,role):
                    if view[0]!='body':return False
                    reads[0]+=1;events.append('scroll');return True
                def press(s,tag,role):
                    self.assertGreaterEqual(reads[0],2);events.append(tag)
                    flow.done.add(flow.key(s,tag,role)+(None,))
                flow.seek=seek;flow.scroll=scroll;flow.press=press
                for _ in range(16):
                    w=dict(tag='ReturnRead' if view[0]=='action' else 'ReviewBody',owner=owner,enabled=reads[0]>=2 if view[0]=='action' else True)
                    flow.review(base|dict(widgets=[w]),'ReturnRead',owner,ack=ack)
                self.assertEqual(reads,[2]);self.assertEqual(events.count('ReturnRead'),1)

    def test_protected_context_never_seeks_scrolls_acknowledges_or_arms(self):
        from unittest import mock
        for protected in ('secret_input','host_input'):
            flow=F.FullFlow(mock.Mock(),mock.Mock(),mock.Mock(),None)
            s=observed_snapshot(phase='ReturnReadReview',subphase='None',owner='Signer1',secret_input=False,host_input=False,widgets=[])
            s[protected]=True;flow.scroll=mock.Mock();flow.seek=mock.Mock();flow.press=mock.Mock()
            self.assertFalse(flow.review(s,'ReturnRead','Signer1'))
            flow.scroll.assert_not_called();flow.seek.assert_not_called();flow.press.assert_not_called()
    def test_pending_body_is_context_keyed_and_disabled_body_waits(self):
        from unittest import mock
        flow=F.FullFlow(mock.Mock(),mock.Mock(),mock.Mock(),None)
        base=observed_snapshot(phase='ReturnReadReview',subphase='None',owner='Signer1',secret_input=False,host_input=False)
        action=dict(tag='ReturnRead',owner='Signer1',enabled=False)
        flow.scroll=mock.Mock(return_value=False);flow.seek=mock.Mock();flow.press=mock.Mock()
        flow.review(base|dict(widgets=[action]),'ReturnRead','Signer1',ack=None)
        pending=('ReturnReadReview','None','review-scroll-pending','ReturnRead','Signer1','ReviewBody')
        self.assertIn(pending,flow.scrolls)
        flow.scroll.reset_mock();flow.seek.reset_mock()
        body=dict(tag='ReviewBody',owner='Signer1',enabled=False)
        self.assertFalse(flow.review(base|dict(widgets=[body]),'ReturnRead','Signer1',ack=None))
        flow.scroll.assert_not_called();flow.seek.assert_not_called();flow.press.assert_not_called()
        for changes in ({'phase':'SignReadReview'},{'subphase':'ReadReview'},{'owner':'Signer2'}):
            changed=base|changes|dict(widgets=[]);flow.seek.reset_mock()
            flow.review(changed,'ReturnRead',changed['owner'],ack=None)
            flow.seek.assert_called_once_with(changed,'ReturnRead',changed['owner'])
        self.assertIn(pending,flow.scrolls) # old context never interpreted as current work
    def test_run_discards_pending_scrolls_when_context_changes(self):
        from unittest import mock
        for field,value in (('phase','SignReadReview'),('subphase','ReadReview'),('owner','Signer2')):
            flow=F.FullFlow(mock.Mock(),mock.Mock(),mock.Mock(),None)
            base=observed_snapshot(phase='ReturnReadReview',subphase='None',owner='Signer1',secret_input=False,host_input=False,widgets=[])
            flow.startup_index=len(F.HOST_STARTUP);base['focused']=True
            snapshots=iter((base,base|{field:value}));flow.snapshot=lambda:next(snapshots)
            flow.pump_host=lambda s:False;calls=[]
            class End(Exception):pass
            def review(s,action,owner):
                if calls:
                    self.assertEqual(flow.scrolls,{})
                    raise End()
                flow.scrolls[('old-context','pending')]=1;calls.append(s.copy())
            flow.review=review
            with self.assertRaises(End):flow.run()
    def test_real_ack_attempt_precedes_body_scroll_and_enabled_action(self):
        from unittest import mock
        flow=F.FullFlow(mock.Mock(),mock.Mock(),mock.Mock(),None)
        base=observed_snapshot(phase='ReturnReadReview',subphase='None',owner='Signer1',secret_input=False,host_input=False)
        events=[]
        def press(s,tag,owner):
            events.append(tag);flow.done.add(flow.key(s,tag,owner)+(None,))
        flow.press=press;flow.seek=lambda s,t,o:events.append('seek:'+t)
        flow.scroll=lambda s,b,o:events.append('scroll:'+b) or True
        flow.review(base|dict(widgets=[dict(tag='ReviewAcknowledgement',owner='Signer1',enabled=True)]),'ReturnRead','Signer1')
        flow.review(base|dict(widgets=[dict(tag='ReturnRead',owner='Signer1',enabled=False),dict(tag='ReviewBody',owner='Signer1',enabled=True)]),'ReturnRead','Signer1')
        flow.review(base|dict(widgets=[dict(tag='ReturnRead',owner='Signer1',enabled=True)]),'ReturnRead','Signer1')
        self.assertEqual(events,['ReviewAcknowledgement','scroll:ReviewBody','ReturnRead'])
