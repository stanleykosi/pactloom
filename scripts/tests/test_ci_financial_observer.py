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
                return dict(phase='Finished',subphase='None',owner=None,
                    view_generation=self.generation,focused=True,secret_input=False,
                    host_input=False,pixels_per_point=1,viewport=[1280,800],
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


class PrivateHostStartupProbeTests(unittest.TestCase):
    PROMPTS=('Existing original Host profile directory (absolute):',
             'Existing original dispatcher workspace directory (absolute):',
             'Storage passphrase:', 'Exact immutable command keys JSON file',
             'Exact coordinated reviewer selection JSON')
    def flow(self, *, render=None, unfocused_until=0, bad=None, repeat=0):
        from unittest import mock
        controller=mock.Mock();fixture=mock.Mock();fixture.deadline_ns=123
        fixture.top_path.side_effect=lambda key:'/synthetic/'+key
        fixture.secret.return_value=object()
        fixture.source.side_effect=AssertionError('no reviewer/source data')
        state={'generation':0,'step':0,'editing':False,'captures':0,'typed':[],
               'submissions':0,'remaining':repeat,'progress':0}
        def progress():
            state['progress']+=1
            if state['progress']>F.S.K.MAX_PROGRESS:raise F.S.K.Rejected('limit')
        controller.wait_render_progress.side_effect=progress
        class Observer:
            expected_profile=F.C.EXTERNAL_PROFILE
            def read(self):return []
            def next_snapshot(self,deadline):
                state['generation']+=1
                widgets=[dict(tag='ScrollRegion',owner=None,rect=[0,0,1280,800],enabled=True)]
                for tag,y in (('HostEditor',100),('HostSubmit',150)) if state['editing'] else (('HostOutput',200),('BeginHostLine',250)):
                    widgets.append(dict(tag=tag,owner=None,rect=[10,y,110,y+20],enabled=True))
                value=dict(phase='Selecting',owner=None,subphase='None',view_generation=state['generation'],
                    focused=state['generation']>unfocused_until,host_input=state['editing'],secret_input=False,
                    pixels_per_point=1,viewport=[1280,800],widgets=widgets)
                if bad:value.update(bad(state))
                return value
        def click(x,y):
            if y==260:
                self.assertFalse(state['editing']);self.assertLess(state['step'],4)
                state['editing']=True
            elif y==160:
                self.assertTrue(state['editing']);self.assertEqual(len(state['typed']),state['step']+1)
                state['editing']=False;state['step']+=1;state['submissions']+=1
            else:raise AssertionError('unexpected native action')
        controller.click.side_effect=click
        flow=F.FullFlow(controller,fixture,Observer(),None)
        def capture(*args):
            self.assertFalse(state['editing']);state['captures']+=1
            if render:return render(state)
            if state['step'] and state['remaining']:
                state['remaining']-=1
                return self.PROMPTS[state['step']-1]
            return '\n'.join(self.PROMPTS[:state['step']+1])
        flow.native.capture_host=mock.Mock(side_effect=capture)
        flow.native.public_host_line=mock.Mock(side_effect=lambda *args:state['typed'].append(('public',args[-1])))
        flow.native.protected_input=mock.Mock(side_effect=lambda *args:state['typed'].append(('secret',None)))
        flow.pump_host=mock.Mock(side_effect=AssertionError('full flow forbidden'))
        flow.expected_host_line=mock.Mock(side_effect=AssertionError('reviewer generator forbidden'))
        return flow,controller,state
    def reject(self,flow,code):
        import contextlib,io,itertools
        from unittest import mock
        output=io.StringIO();clock=itertools.count(10_000_000_000,1_000_000_000)
        with contextlib.redirect_stdout(output),contextlib.redirect_stderr(output), \
             mock.patch.object(F.time,'monotonic_ns',side_effect=lambda:next(clock)):
            with self.assertRaises((F.C.Rejected,F.S.K.Rejected)) as error:flow.host_startup_probe()
        self.assertEqual(error.exception.code,code);self.assertEqual(output.getvalue(),'')
        flow.pump_host.assert_not_called();flow.expected_host_line.assert_not_called()
        flow.fixture.source.assert_not_called();flow.controller.focus.assert_not_called()
        flow.controller.terminal_click.assert_not_called()
        self.assertEqual(flow.fixture.deadline_ns,123)
    def test_exact_initial_sequence_stops_before_reviewer_json(self):
        flow,controller,state=self.flow()
        self.reject(flow,'missing_evidence')
        self.assertEqual(state['typed'],[('public','/synthetic/profile'),('public','/synthetic/workspace'),
                          ('secret',None),('public','/synthetic/session_commands_file')])
        self.assertEqual(state['submissions'],4);self.assertEqual(flow.host_lines,4)
        self.assertEqual(flow.actions,8);self.assertEqual(len(flow.done),8)
        flow.fixture.secret.assert_called_once_with('host')
        self.assertEqual(flow.location,dict(phase='Selecting',subphase='None',owner=None))
    def test_delayed_startup_focus_observes_without_refocus(self):
        flow,controller,state=self.flow(unfocused_until=3)
        self.reject(flow,'missing_evidence')
        self.assertEqual([c[0] for c in controller.mock_calls[:3]],['wait_render_progress']*3)
        self.assertEqual(state['submissions'],4)
    def test_never_focused_no_input_or_capture(self):
        flow,controller,state=self.flow(unfocused_until=1000)
        self.reject(flow,'input_budget');controller.click.assert_not_called()
        flow.native.capture_host.assert_not_called();self.assertEqual(state['generation'],64)
    def test_repeated_previous_prompt_is_not_resubmitted(self):
        flow,controller,state=self.flow(repeat=3)
        self.reject(flow,'missing_evidence');self.assertEqual(state['submissions'],4)
        self.assertEqual(flow.host_lines,4);self.assertGreater(state['captures'],5)
    def test_stale_earlier_prompt_never_establishes_stop(self):
        flow,controller,state=self.flow(render=lambda s:self.PROMPTS[0])
        self.reject(flow,'input_budget');self.assertEqual(state['submissions'],1)
        self.assertEqual(flow.host_lines,1)
    def test_future_or_reviewer_prompt_cannot_skip_any_prerequisite(self):
        for reached in range(4):
            for future in range(reached+1,5):
                with self.subTest(reached=reached,future=future):
                    flow,controller,state=self.flow(render=lambda s,r=reached,f=future:self.PROMPTS[f if s['step']==r else s['step']])
                    self.reject(flow,'input_phase');self.assertEqual(state['submissions'],reached)
    def test_reviewer_followed_by_newer_earlier_marker_does_not_stop(self):
        flow,controller,state=self.flow(render=lambda s: '\n'.join(self.PROMPTS) if s['step']<4 else self.PROMPTS[4]+' '+self.PROMPTS[0])
        self.reject(flow,'input_phase');self.assertEqual(state['submissions'],0)
        flow,controller,state=self.flow(render=lambda s:self.PROMPTS[s['step']] if s['step']<4 else self.PROMPTS[4]+' '+self.PROMPTS[0])
        self.reject(flow,'input_budget');self.assertEqual(state['submissions'],4)
    def test_unknown_output_is_bounded_and_never_typed(self):
        flow,controller,state=self.flow(render=lambda s:'private output must never escape')
        self.reject(flow,'input_budget');controller.click.assert_not_called()
    def test_bad_terminal_secret_or_unowned_protected_state_fails_closed(self):
        for change in ({'phase':'Finished'},{'phase':'Revoked'},{'phase':'V3Configuring'},
                       {'owner':'Signer1'},{'subphase':'Idle'},{'secret_input':True},{'host_input':True}):
            with self.subTest(change=change):
                flow,controller,state=self.flow(bad=lambda s,c=change:c)
                self.reject(flow,'input_phase');controller.click.assert_not_called()
                flow.native.capture_host.assert_not_called()
    def test_focus_loss_after_seen_fails_and_never_retries(self):
        flow,controller,state=self.flow(bad=lambda s:{'focused':False} if s['generation']>3 else {})
        self.reject(flow,'input_phase');self.assertEqual(controller.click.call_count,1)
    def test_bad_post_typing_snapshot_prevents_submit(self):
        flow,controller,state=self.flow(bad=lambda s:{'phase':'Finished'} if s['typed'] else {})
        self.reject(flow,'input_phase');self.assertEqual(state['submissions'],0)
        self.assertEqual(len(state['typed']),1);self.assertEqual(controller.click.call_count,1)
    def test_begin_without_editor_never_retries_or_types(self):
        flow,controller,state=self.flow(bad=lambda s:{'host_input':False} if s['editing'] else {})
        self.reject(flow,'limit');self.assertEqual(controller.click.call_count,1)
        self.assertEqual(state['typed'],[]);self.assertEqual(state['captures'],1)
    def test_owned_submitted_slot_waits_without_capture_or_resubmit(self):
        flow,controller,state=self.flow(bad=lambda s:{'host_input':True} if s['submissions'] else {})
        self.reject(flow,'limit');self.assertEqual(controller.click.call_count,2)
        self.assertEqual(state['submissions'],1);self.assertEqual(state['captures'],1)
    def test_delayed_writing_to_idle_does_not_exhaust_startup_bound(self):
        remaining={'waits':100}
        def delay(s):
            if s['submissions']==1 and remaining['waits']:
                self.assertEqual(s['captures'],1) # no OCR during legitimate Writing
                remaining['waits']-=1
                return {'host_input':True}
            return {}
        flow,controller,state=self.flow(bad=delay,repeat=3)
        self.reject(flow,'missing_evidence')
        self.assertEqual(remaining['waits'],0);self.assertEqual(state['submissions'],4)
        self.assertGreater(state['progress'],100);self.assertEqual(flow.host_lines,4)
    def test_container_routes_only_private_host_probe(self):
        source=(ROOT/'ci-financial-container.py').read_text()
        self.assertIn('self.flow.host_startup_probe()',source)
        self.assertNotIn('self.flow.run()',source)
        self.assertNotIn('self.flow.initial_selection_probe()',source)

if __name__=='__main__':unittest.main()



