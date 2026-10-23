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



class ClickRenderBoundaryTests(unittest.TestCase):
    # Native witness: host-line-frame-audit/harness.rs, actual egui0.36.2 +
    # unchanged HostLineInput. Coalesced click+first32 dropped that first batch;
    # a rendered click-only frame preserved all34 synthetic Host bytes.
    def recording(self,fail_barrier=False):
        import test_ci_financial_input_batching as B
        class Recording(B.RecordingController):
            def __init__(self):super().__init__();self.trace=[]
            def _command(self,op,a=0,b=0):
                self.trace.append((op,a,b));super()._command(op,a,b)
                return (op,a,b,self._sequence)
            def wait_render_progress(self):
                self.trace.append(('render',))
                if fail_barrier:raise B.K.Rejected('protocol')
                return super().wait_render_progress()
        from unittest import mock
        controller=Recording()
        self.configured_flow=F.FullFlow(controller,mock.Mock(),
            mock.Mock(expected_profile=F.C.EXTERNAL_PROFILE),mock.Mock())
        return controller,B
    def protected(self,c,B):
        native=self.configured_flow.native
        self.assertIs(native.controller,c)
        native.stable=lambda *a,**kw:dict(host_input=True,secret_input=False,
            host_observation=dict(revision=1,nonws_end=8,context_valid=True,entry='Editing',
                editor=dict(ordinal=1,revision=1),view=None))
        native.point=lambda *a:(100,100)
        secret=F.S.F.SyntheticSecret(F.S.F._TOKEN,F.S.F._SYNTHETIC_PASSWORDS['host'])
        return native,secret
    def test_click_returns_release_receipt_only_after_rendered_boundary(self):
        c,B=self.recording();receipt=c.click(100,100)
        self.assertEqual(receipt,(K.BUTTON,0,0,3))
        self.assertEqual(c.trace,[(K.MOVE,100,100),(K.BUTTON,1,0),(K.BUTTON,0,0),('render',)])
        self.assertEqual((c._sequence,c._progress),(4,1))
    def test_actual_protected_input_click_release_render_then_exact_first_key(self):
        c,B=self.recording();native,secret=self.protected(c,B)
        native.protected_input('Selecting',None,'HostEditor',secret,(0,8,1))
        expected=B.K._ascii_events(B.S.F._SYNTHETIC_PASSWORDS['host'].decode('ascii'))
        self.assertEqual(c.trace[:5],[(K.MOVE,100,100),(K.BUTTON,1,0),(K.BUTTON,0,0),
            ('render',),(K.KEY,*expected[0])])
        self.assertEqual(tuple((a,b) for op,a,b in c.commands if op==K.KEY),expected)
        self.assertEqual(tuple(map(len,c.batches)),(0,64,4))
        self.assertEqual((c._sequence,c._progress),(74,3))
        self.assertFalse(c.held);self.assertTrue(all(v==0 for v in secret._bytes))
    def test_click_barrier_failure_sends_no_keys_and_wipes_secret(self):
        c,B=self.recording(True);native,secret=self.protected(c,B)
        with self.assertRaises(B.K.Rejected):
            native.protected_input('Selecting',None,'HostEditor',secret,(0,8,1))
        self.assertEqual([op for op,a,b in c.commands],[K.MOVE,K.BUTTON,K.BUTTON])
        self.assertTrue(all(v==0 for v in secret._bytes))
    def test_click_budget_failure_before_any_pointer_input(self):
        for kind in ('commands','progress'):
            c,B=self.recording()
            if kind=='commands':c._sequence=K.MAX_COMMANDS-3
            else:c._progress=K.MAX_PROGRESS
            with self.assertRaises(B.K.Rejected):c.click(100,100)
            self.assertEqual(c.trace,[])
    def test_whole_secret_preflight_includes_click_barrier_and_exact_boundary(self):
        for kind in ('commands','progress'):
            for fits in (False,True):
                with self.subTest(kind=kind,fits=fits):
                    c,B=self.recording();native,secret=self.protected(c,B)
                    if kind=='commands':c._sequence=K.MAX_COMMANDS-(74 if fits else 73)
                    else:c._progress=K.MAX_PROGRESS-(3 if fits else 2)
                    if fits:
                        native.protected_input('Selecting',None,'HostEditor',secret,(0,8,1))
                        self.assertEqual(c._sequence if kind=='commands' else c._progress,
                                         K.MAX_COMMANDS if kind=='commands' else K.MAX_PROGRESS)
                    else:
                        with self.assertRaises(B.K.Rejected):
                            native.protected_input('Selecting',None,'HostEditor',secret,(0,8,1))
                        self.assertEqual(c.trace,[])
                    self.assertTrue(all(v==0 for v in secret._bytes))
    def test_private_preflight_contract_rejects_unrecognized_reservations(self):
        for extra in (-1,1,4,True,None):
            c,B=self.recording()
            with self.assertRaises(B.K.Rejected):c._preflight_ascii_batches('a',extra_commands=extra)
            self.assertEqual(c.trace,[])
    def test_full_flow_unconditionally_enables_mode_before_any_input(self):
        from unittest import mock
        import test_ci_financial_input_batching as B
        c=B.RecordingController();self.assertFalse(c._rendered_clicks)
        observer=mock.Mock(expected_profile=F.C.EXTERNAL_PROFILE)
        F.FullFlow(c,mock.Mock(),observer,mock.Mock())
        self.assertTrue(c._rendered_clicks);self.assertEqual(c.commands,[])
        c.enable_rendered_clicks();self.assertTrue(c._rendered_clicks)
        c.click(100,100);self.assertEqual((c._sequence,c._progress),(4,1))
    def test_full_flow_configuration_cannot_be_disabled_by_instance_override(self):
        from unittest import mock
        import test_ci_financial_input_batching as B
        class Override(B.RecordingController):
            def enable_rendered_clicks(self):pass
        c=Override();c.enable_rendered_clicks();self.assertFalse(c._rendered_clicks)
        F.FullFlow(c,mock.Mock(),mock.Mock(expected_profile=F.C.EXTERNAL_PROFILE),mock.Mock())
        c.enable_rendered_clicks();self.assertTrue(c._rendered_clicks)
        c.click(100,100);self.assertEqual((c._sequence,c._progress),(4,1))
    def test_enabled_public_host_path_renders_focus_before_typing(self):
        c,B=self.recording();native,secret=self.protected(c,B);secret.wipe()
        native.public_host_line('Selecting',None,'public-path',(0,8,1))
        self.assertEqual(c.trace[2:5],[(K.BUTTON,0,0),('render',),(K.KEY,*B.K._ascii_events('p')[0])])
        self.assertEqual(tuple((a,b) for op,a,b in c.commands if op==K.KEY),B.K._ascii_events('public-path'))
    def test_full_flow_public_form_renders_click_before_clear_and_text(self):
        c,B=self.recording();native,secret=self.protected(c,B);secret.wipe()
        snapshot=observed_snapshot(phase='Selecting',subphase='None',owner=None,
            view_generation=1,focused=True,host_input=False,secret_input=False,
            pixels_per_point=1,viewport=[1280,800],widgets=[dict(tag='Field:HostProfile',
                owner=None,rect=[90,90,110,110],enabled=True)])
        F.C.validate_snapshot(snapshot)
        native.stable=lambda *a,**kw:snapshot
        native.point=F.S.NativeScenario.point.__get__(native)
        native.public_field('Selecting',None,'Field:HostProfile','path')
        self.assertEqual(c.trace[2:5],[(K.BUTTON,0,0),('render',),(K.KEY,29,1)])
        self.assertFalse(c.held)
    def test_full_flow_source_password_renders_click_before_first_key(self):
        c,B=self.recording();native,secret=self.protected(c,B)
        secret.wipe()
        secret=F.S.F.SyntheticSecret(F.S.F._TOKEN,F.S.F._SYNTHETIC_PASSWORDS['source'])
        native.stable=lambda *a,**kw:dict(host_input=False,secret_input=True)
        native.protected_input('V3Confirm','Signer1','SourcePassword',secret)
        first=B.K._ascii_events(F.S.F._SYNTHETIC_PASSWORDS['source'].decode('ascii'))[0]
        self.assertEqual(c.trace[2:5],[(K.BUTTON,0,0),('render',),(K.KEY,*first)])
        self.assertTrue(all(v==0 for v in secret._bytes))
    def test_standalone_legacy_click_keeps_original_contract(self):
        import test_ci_financial_input_batching as B
        c=B.RecordingController();c.click(100,100)
        self.assertEqual((c._sequence,c._progress),(3,0));self.assertEqual(c.batches,[])
    def test_terminal_close_remains_release_then_ack_without_render_wait(self):
        from unittest import mock
        transport=NativeAckTransport()
        c=K.Controller(transport,1_000_000_000,1_000_000_000,_clock=lambda:1)
        c._ready=c._bound=True;c.enable_rendered_clicks();self.addCleanup(c.close)
        with mock.patch.object(K.Controller,'wait_render_progress',side_effect=AssertionError('post-close render')):
            receipt=c.terminal_click(100,100)
        self.assertEqual([command[3] for command in transport.commands],[K.MOVE,K.BUTTON,K.BUTTON])
        self.assertEqual(receipt,K.Receipt(3,13,23,3));self.assertTrue(c._terminal_close)
        self.assertEqual(c._progress,0)

# Pure scheduling regressions: no product, UI, credentials or forged runtime proof.
spec=importlib.util.spec_from_file_location('financial_completion_flow_tested',ROOT/'ci-financial-flow.py')
F=importlib.util.module_from_spec(spec);sys.modules[spec.name]=F;spec.loader.exec_module(F)


class HostBoundaryDiagnosticV2Tests(unittest.TestCase):
    def flow(self):
        from unittest import mock
        f=F.FullFlow(mock.Mock(),mock.Mock(),mock.Mock(expected_profile=F.C.EXTERNAL_PROFILE),None)
        return f
    def snap(self,entry='Idle',revision=1,end=10,coverage='whole'):
        h=dict(revision=revision,nonws_end=end,context_valid=True,entry=entry,
            editor=dict(ordinal=1,revision=revision) if entry=='Editing' else None,
            view=None if coverage=='none' or entry!='Idle' else dict(rect=[10,10,110,30],nonws=end if coverage=='whole' else end-1,rows=1))
        s=observed_snapshot(phase='Selecting',subphase='None',owner=None,view_generation=1,
            focused=True,host_input=entry in ('Editing','Writing'),secret_input=False,
            pixels_per_point=1,viewport=[1280,800],host_observation=h,widgets=[
                dict(tag='HostOutput',owner=None,rect=[0,0,120,40],enabled=True)])
        F.C.validate_snapshot(s);return s
    def test_v1_unchanged_and_v2_unobserved_has_only_closed_fields(self):
        old=dict(version=1,category='none',startup_stage='Financial',attempted_lines=4)
        self.assertEqual(F.C.validate_host_diagnostic(old),old)
        value=self.flow().host_diagnostic();F.C.validate_host_diagnostic(value)
        self.assertEqual(value['observation'],dict(entry='Unobserved',context_valid=None,
            pending_context='Unobserved',coverage='Unobserved',capture_outcome='Unobserved',capture_context='Unobserved'))
    def test_current_pending_relation_is_projected_after_cached_idle(self):
        f=self.flow();f.cache_host_observation(self.snap()['host_observation'])
        self.assertEqual(f.host_diagnostic()['observation']['pending_context'],'NoPending')
        f.pending_occurrence=(0,10,1);f.pending_host=('secret','NEVER_PRINT_ME')
        self.assertEqual(f.host_diagnostic()['observation']['pending_context'],'Same')
        f.pending_occurrence=(0,11,2)
        self.assertEqual(f.host_diagnostic()['observation']['pending_context'],'Changed')
        self.assertNotIn('NEVER_PRINT_ME',json.dumps(f.host_diagnostic()))
    def test_cached_coverage_does_not_claim_prompt_completeness(self):
        f=self.flow()
        for coverage,expected in (('none','Unavailable'),('partial','TailSuffix'),('whole','WholeRetained')):
            f.cache_host_observation(self.snap(coverage=coverage)['host_observation'])
            self.assertEqual(f.host_diagnostic()['observation']['coverage'],expected)
        f.host_capture_context=(1,10);f.host_capture_outcome='host_capture_grammar'
        self.assertEqual(f.host_diagnostic()['observation']['capture_context'],'Same')
        f.cache_host_observation(self.snap(revision=2,end=11)['host_observation'])
        self.assertEqual(f.host_diagnostic()['observation']['capture_context'],'Changed')
        f.host_capture_context=None
        self.assertEqual(f.host_diagnostic()['observation']['capture_context'],'Unobserved')
    def pending(self):
        from unittest import mock
        f=self.flow();s=self.snap('Editing',coverage='none')
        f.host_lines=1;f.pending_host=('public','synthetic');f.pending_occurrence=(0,10,1)
        f.startup_issued=f.pending_startup=0;f.cache_host_observation(s['host_observation'])
        f.native=mock.Mock();f.native.check_host_editor=F.S.NativeScenario.check_host_editor
        f.snapshot=mock.Mock(return_value=s);f.press=mock.Mock()
        return f,s
    def test_begin_request_return_boundaries_and_cached_pre_begin_context(self):
        from unittest import mock
        for fails in (True,False):
            f=self.flow();s=self.snap();f.cache_host_observation(s['host_observation'])
            f.host_prepared=((0,10,1),('public','synthetic'))
            f.find=mock.Mock(return_value={'enabled':True});f.press=mock.Mock()
            f.native.public_host_line=mock.Mock()
            if fails:f.press.side_effect=F.C.Rejected('deadline')
            if fails:
                with self.assertRaises(F.C.Rejected):f.pump_host(s)
            else:self.assertTrue(f.pump_host(s))
            d=F.C.validate_host_diagnostic(f.host_diagnostic())
            self.assertEqual(d['boundary']['action'],'BeginRequested' if fails else 'BeginReturned')
            self.assertTrue(d['boundary']['pending_host']);self.assertEqual(d['observation']['pending_context'],'Same')
            f.press.assert_called_once();f.native.public_host_line.assert_not_called()
    def test_typing_submit_failures_never_claim_call_return_or_acceptance(self):
        for stop,expected in (('typing','TypingRequested'),('snapshot','TypingReturned'),('submit','SubmitRequested'),('none','SubmitReturned')):
            f,s=self.pending()
            if stop=='typing':f.native.public_host_line.side_effect=F.C.Rejected('deadline')
            elif stop=='snapshot':f.snapshot.side_effect=F.C.Rejected('deadline')
            elif stop=='submit':f.press.side_effect=F.C.Rejected('deadline')
            if stop!='none':
                with self.assertRaises(F.C.Rejected):f.pump_host(s)
            else:self.assertTrue(f.pump_host(s))
            d=F.C.validate_host_diagnostic(f.host_diagnostic());b=d['boundary']
            self.assertEqual(b['action'],expected);self.assertEqual(b['pending_host'],stop!='none')
            self.assertEqual(b['startup_index'],1 if stop=='none' else 0)
            self.assertEqual(b['waiting'],stop=='none')
            self.assertEqual(d['observation']['entry'],'Editing') # cached, not claimed current
            f.native.public_host_line.assert_called_once()
    def test_submit_returned_persists_through_writing_until_observed_idle(self):
        f,s=self.pending();f.pump_host(s)
        writing=self.snap('Writing',coverage='none');f.cache_host_observation(writing['host_observation'])
        self.assertTrue(f.pump_host(writing));self.assertEqual(f.host_diagnostic()['boundary']['action'],'SubmitReturned')
        f.host_occurrences.frontier=10
        idle=self.snap();f.cache_host_observation(idle['host_observation']);self.assertFalse(f.pump_host(idle))
        self.assertEqual(f.host_diagnostic()['boundary']['action'],'NoPending');self.assertFalse(f.startup_waiting)
    def test_successful_inspection_replaces_stale_grammar_without_fake_submission(self):
        import test_ci_financial_host_context as T
        f=T.PumpTests().make();f.text=': ';f.current['host_observation']=T.observation(f.text,1,T.H.count(T.PROMPT))
        f.pump_host(f.current);self.assertEqual(f.host_capture_outcome,'host_capture_grammar')
        f.text=T.PROMPT;f.current['host_observation']=T.observation(T.PROMPT);f.last_ocr=0
        f.pump_host(f.current)
        d=F.C.validate_host_diagnostic(f.host_diagnostic())
        self.assertEqual(d['category'],'none');self.assertEqual(d['observation']['capture_outcome'],'Accepted')
        self.assertEqual(d['boundary']['action'],'BeginReturned');self.assertTrue(d['boundary']['pending_host'])
        self.assertEqual(f.inputs,['BeginHostLine'])
    def test_capture_failure_does_not_reuse_prior_bound_context(self):
        import test_ci_financial_host_context as T
        f=T.PumpTests().make();f.host_capture_context=(1,1);f.host_capture_outcome='Accepted'
        rejection=f.pump_host.__func__.__globals__['C'].Rejected
        def failed(*a):raise rejection('snapshot')
        f.native.capture_host=failed
        with self.assertRaises(rejection):f.pump_host(f.current)
        d=f.host_diagnostic()['observation'];self.assertEqual(d['capture_outcome'],'capture_guard')
        self.assertEqual(d['capture_context'],'Unobserved')
    def test_validator_rejects_unknown_keys_types_enums_bounds_and_payloads(self):
        import copy
        good=self.flow().host_diagnostic()
        mutations=[((), 'version',v) for v in (True,0,3,'2')]
        mutations += [((), 'raw_text','secret'),(('boundary',),'raw_path','/private'),(('observation',),'pixels',[])]
        for key in ('startup_index','issued_index','pending_index'):
            mutations += [(('boundary',),key,v) for v in (True,-2,14,'0',None)]
        for key in ('pending_host','input_attempted','waiting'):
            mutations += [(('boundary',),key,v) for v in (0,1,None,'secret')]
        for key in ('action',):mutations += [(('boundary',),key,v) for v in (None,[],{},'secret')]
        for key in ('entry','pending_context','coverage','capture_outcome','capture_context'):
            mutations += [(('observation',),key,v) for v in (None,[],{},'secret')]
        mutations += [(('observation',),'context_valid',v) for v in (True,False,0,'secret')]
        for path,key,value in mutations:
            bad=copy.deepcopy(good);target=bad
            for component in path:target=target[component]
            target[key]=value
            with self.subTest(path=path,key=key,value=value):
                with self.assertRaises(F.C.Rejected):F.C.validate_host_diagnostic(bad)
        for section in ('boundary','observation'):
            for key in good[section]:
                bad=copy.deepcopy(good);del bad[section][key]
                with self.assertRaises(F.C.Rejected):F.C.validate_host_diagnostic(bad)
    def test_failure_projection_and_stdout_failure_make_no_new_observation(self):
        from unittest import mock
        f=self.flow();f.snapshot=mock.Mock(side_effect=AssertionError('new observation'))
        container=F.load('ci-financial-container')
        with mock.patch('builtins.print',side_effect=BrokenPipeError):container.emit_cached_host_failure(f)
        f.snapshot.assert_not_called();self.assertEqual(f.controller.mock_calls,[])
        F.C.validate_host_diagnostic(f.host_diagnostic())
    def test_supervisor_v2_failure_only_duplicate_and_post_result_rejection(self):
        import io,contextlib
        supervisor=F.load('ci-financial-supervisor');d=self.flow().host_diagnostic()
        line=b'CI_FINANCIAL_HOST_DIAGNOSTIC '+json.dumps(d).encode()
        records=supervisor.RuntimeRecords('external');output=io.StringIO()
        with contextlib.redirect_stdout(output):records(line)
        self.assertEqual(output.getvalue(),'')
        with self.assertRaises(supervisor.Failure):records(line)
        records=supervisor.RuntimeRecords('external');records(line)
        with contextlib.redirect_stdout(output):records(b'CI_FINANCIAL_RESULT '+json.dumps(supervisor.P.failure('deadline')).encode())
        self.assertIn('HOST_DIAGNOSTIC',output.getvalue())
        with self.assertRaises(supervisor.Failure):records(line)
        records=supervisor.RuntimeRecords('external');records(line)
        candidate=dict(schema=1,profile=supervisor.P.C.EXTERNAL_PROFILE,native_oracle_verified=True,
            fixture_cleaned=True,display_cleaned=True,public_chain_verified=False,dispatch_attempted=False)
        with self.assertRaises(supervisor.Failure):records(b'CI_FINANCIAL_CANDIDATE '+json.dumps(candidate).encode())

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
                'proposal':{'manifest':{'agreement':{'agreement_id':'synthetic-agreement'}}},
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
        flow=F.FullFlow(mock.Mock(),self.fixture,observer,None)
        return flow
    def acknowledge(self,flow):
        flow.pending_startup=flow.startup_index;flow.startup_submitted();flow.startup_waiting=False
    def test_whole_real_prompt_sequence_has_exact_prepare_responses_and_separate_latches(self):
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
            ('public','synthetic-roster-host'),('public','OWNED'),('public',''),('public','PREPARE'),('public',''),
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
            self.fixture._data['sources'][source]['original_capture']['scope']['proposal']['manifest']['agreement']['agreement_id']='other'
            with self.assertRaises((F.C.Rejected,F.S.F.C.Rejected)):self.fixture.validate_host_startup()
        self.fixture._data=original;self.fixture._data['purpose']='unrecognized'
        with self.assertRaises((F.C.Rejected,F.S.F.C.Rejected)):self.fixture.validate_host_startup()
    def test_native_nested_proposal_schema_is_bound_to_rust_sources(self):
        root=pathlib.Path(__file__).resolve().parents[2]
        def body(path,name):
            text=(root/path).read_text()
            return text.split('pub struct '+name+' {',1)[1].split('}',1)[0]
        self.assertIn('pub manifest: ProposalManifest,',body('crates/wholepact-core/src/proposal.rs','ProposalInput'))
        self.assertNotIn('pub agreement_id:',body('crates/wholepact-core/src/proposal.rs','ProposalInput'))
        self.assertIn('pub agreement: AgreementDraft,',body('crates/wholepact-core/src/proposal.rs','ProposalManifest'))
        self.assertIn('pub agreement_id: String,',body('crates/wholepact-core/src/agreement.rs','AgreementDraft'))
        self.assertIn('pub proposal: ProposalInput,',body('crates/wholepact-wallet/src/durable_construction_v1.rs','DurableConstructionScopeV1'))
        creator=next(root.rglob('coordinated_full_fixture_v1.rs')).read_text()
        capture=next(root.rglob('private_fixed_v2.rs')).read_text()
        self.assertIn('"request": captured.history, "scope": captured.scope,',creator)
        self.assertIn('scope: DurableConstructionScopeV1 {',capture)
        self.assertIn('proposal: session.proposal().clone(),',capture)
        flow=self.flow()
        self.assertEqual(flow.expected_host_line(self.PROMPTS[0]),('public',self.fixture._data['profile']))
        self.assertEqual(flow.startup_issued,0)
        self.assertEqual(flow.host_occurrences.attempts,0)
        flow.controller.click.assert_not_called()

    def test_other_startup_and_reviewer_field_paths_match_native_serialized_types(self):
        # Source-bound schema witness, not execution of serde or a product fixture.
        # Every new consumed path is traced to a declared serialized Rust field.
        root=pathlib.Path(__file__).resolve().parents[2]
        def fields(path,name,expected):
            text=(root/path).read_text();head,tail=text.split('struct '+name+' {',1)
            self.assertIn('Serialize',head[-250:])
            body=tail.split('}',1)[0]
            for field,kind in expected.items():self.assertIn('pub '+field+': '+kind+',',body)
            self.assertNotIn('serde(flatten)',body)
        fields('crates/wholepact-protocol/src/durable_proposal_v1.rs','FixedProposalIdentityV1',
               {'agreement_id':'String'})
        fields('crates/wholepact-wallet/src/durable_construction_v1.rs','DurableConstructionScopeV1',
               {'proposal':'ProposalInput','account_id':'String','participant_id':'String',
                'constructor':'ConstructionRecipientV1','prover':'ConstructionRecipientV1'})
        fields('crates/wholepact-wallet/src/durable_construction_v1.rs','ConstructionRecipientV1',
               {'principal_id':'String','authenticated_local_grant_digest':'String'})
        fields('crates/wholepact-signer/src/authority_bridge/durable_construction_v1.rs','DurableConstructionHistoryRequestV1',
               {'operation_id':'String','expected_request_digest':'String'})
        fields('crates/wholepact-signer/src/native_ui/qualification/durable_proposal_v1.rs','DurableDeliveryReopenSelectorV2',
               {'account_id':'String','owner_setup_json':'String'})
        fields('crates/wholepact-native-host/src/host/financial/durable_delivery_admission_v2.rs','DeliveryChoicesV2',
               {'submission_operation_id':'String','provider':'wholepact_core::manual_construction::PreconstructionProvider',
                'route':'DurableDeliveryRouteV2','minimum_expiry_margin_blocks':'u32',
                'maximum_fresh_admission_lifetime_ms':'u64','maximum_explicitly_approved_attempts':'u32'})
        fields('crates/wholepact-core/src/manual_construction.rs','PreconstructionProvider',
               {'source_id':'String','endpoint':'String','trust_profile':'String'})
        route=(root/'crates/wholepact-authority/src/durable_delivery_scope_v2.rs').read_text()
        self.assertIn('#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]',route)
        self.assertIn('Direct {},',route);self.assertIn('ExistingHttpConnect { origin: String },',route)
        creator=next(root.rglob('coordinated_full_fixture_v1.rs')).read_text()
        for field,value in (('profile','profile'),('workspace','workspace'),('financial','financial'),
                            ('fixed_identity','fixed_identity'),('delivery_choices','choices'),
                            ('reopen_selector','selector'),('account_id','account.account_id'),
                            ('request','captured.history'),('scope','captured.scope')):
            self.assertIn('"'+field+'": '+value,creator)
        self.assertIn('"role": if index == 1 { "signer1" } else { "signer2" }',creator)
        for basename in F.S.F._HANDOFF_NAMES.values():self.assertIn('"'+basename+'"',creator)
        self.assertIn('"'+F.S.F.FIXTURE_FILE+'"',creator)
        self.assertIn('create_new(true).mode(0o600)',creator)
        self.assertIn('libc::O_NOFOLLOW | libc::O_CLOEXEC',creator)
        self.assertIn('Permissions::from_mode(0o700)',creator)
        self.assertIn('child.temporary_root().join(READY_FILE)',creator)

    def test_native_nested_agreement_has_no_flattened_fallback(self):
        import copy
        original=copy.deepcopy(self.fixture._data)
        invalid=({'agreement_id':'synthetic-agreement'},
                 {'manifest':{'agreement_id':'synthetic-agreement'}},
                 {'manifest':{'agreement':{}}},
                 {'manifest':{'agreement':{'agreement_id':'other'}},'agreement_id':'synthetic-agreement'},
                 {'manifest':{'agreement':{'agreement_id':None}}},
                 {'manifest':{'agreement':{'agreement_id':[]}}})
        for source in range(2):
            for proposal in invalid:
                with self.subTest(source=source,proposal=proposal):
                    self.fixture._data=copy.deepcopy(original)
                    self.fixture._data['sources'][source]['original_capture']['scope']['proposal']=proposal
                    flow=self.flow()
                    with self.assertRaises((F.C.Rejected,F.S.F.C.Rejected)) as error:
                        flow.expected_host_line(self.PROMPTS[0])
                    self.assertEqual(error.exception.code,'fixture')
                    self.assertIsNone(flow.startup_issued)
                    self.assertEqual(flow.host_occurrences.attempts,0)
                    self.assertEqual(flow.controller.mock_calls,[])
        self.fixture._data=original

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
    def test_synthetic_prepare_selection_satisfies_native_export_permission_membership(self):
        import re
        host=ROOT.parent/'crates/wholepact-native-host/src'
        enrollment=(host/'host.rs').read_text()
        branches=enrollment[enrollment.index('let permissions = match mode.as_str()'):enrollment.index('let browser_origin = self.terminal.ask')]
        grants={mode:set(re.findall(r'Permission::(\w+)',body)) for mode,body in
                re.findall(r'"(READ|PREPARE)" => BTreeSet::from\(\[(.*?)\]\)',branches,re.S)}
        command=(host/'host/manual_enrollment/command.rs').read_text()
        membership=command[command.index('fn has_manual_session_permissions('):]
        membership=membership[:membership.index('#[cfg(test)]')]
        self.assertIn('.all(|permission| permissions.contains(permission))',membership)
        required=set(re.findall(r'Permission::(\w+)',membership))
        self.assertEqual(required,{'Read','Coordinate','Disclose'})
        self.assertEqual(grants['READ'],{'Read'})
        self.assertFalse(required<=grants['READ'],'READ-only fixture setup is not full-export permission')
        mode=self.fixture.host_startup_value('mode')
        self.assertEqual(mode,'PREPARE');self.assertTrue(required<=grants[mode])
        self.assertEqual(grants[mode]-required,{'Propose','Intent'})
        self.assertTrue(grants[mode].isdisjoint({'AuthorizeRequest','Submit','Administer'}))
        # Membership is necessary, not sufficient authority. Native session,
        # identity, exact-target and genuine approval checks remain in force.
        self.assertIn('&& has_manual_session_permissions(&client.permissions)',command)
        export=(host/'host/financial/durable_delivery_admission_v2/closed_review_v3/coordinated_export_v1.rs').read_text()
        self.assertIn('self.require_manual_session()?;',export)
        startup=(host/'host/durable_private_workspace_v1.rs').read_text()
        check=startup[startup.index('fn require_private_workspace_read_session_v1('):]
        self.assertIn('.contains(&wholepact_service::security::Permission::Read)',check)
        self.assertEqual([self.fixture.host_startup_value(k) for k in ('principal','scope','shared','origin')],
                         ['synthetic-roster-host','OWNED','',''])

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
    def _run_revoked_third_host_boundary(self,after_submit):
        from unittest import mock
        from test_ci_financial_input_batching import RecordingController
        flow=self.flow()
        previous_end=0
        for revision,prompt in enumerate(self.PROMPTS[:2],1):
            flow.expected_host_line(prompt);self.acknowledge(flow)
            end=previous_end+F.H.count(prompt)
            flow.host_occurrences.latch((previous_end,end,revision));previous_end=end
        flow.host_lines=2
        text=''.join(self.PROMPTS[:3]);end=F.H.count(text);budget=RecordingController()
        state=dict(mode='Idle',seen_revoked=False,generation=0,effects=[])
        def snapshot():
            state['generation']+=1
            mode=state['mode'];revoked=mode=='Revoked';editing=mode=='Editing'
            if revoked:state['seen_revoked']=True
            h=dict(revision=3,nonws_end=end,context_valid=not revoked,
                   entry='Closed' if revoked else mode,
                   editor=dict(ordinal=3,revision=3) if editing else None,
                   view=dict(rect=[10,200,110,220],nonws=end,rows=1) if mode=='Idle' else None)
            widgets=[] if revoked else ([('HostEditor',100),('HostSubmit',150)] if editing
                else [('HostOutput',200),('BeginHostLine',250)])
            result=observed_snapshot(phase='Revoked' if revoked else 'Selecting',owner=None,
                subphase='None',focused=True,view_generation=state['generation'],
                secret_input=False,host_input=editing,host_observation=h,
                pixels_per_point=1,viewport=[1280,800],widgets=[
                    dict(tag=t,owner=None,rect=[10,y,110,y+20],enabled=True) for t,y in widgets])
            F.C.validate_snapshot(result);return result
        def effect(name):
            self.assertFalse(state['seen_revoked'],'effect after observed terminal state')
            state['effects'].append(name)
        def click(x,y):
            effect('click')
            if y==260:
                self.assertEqual(state['mode'],'Idle')
                state['mode']='Editing' if after_submit else 'Revoked'
            elif y==110:self.assertEqual(state['mode'],'Editing')
            elif y==160:
                self.assertEqual(state['mode'],'Editing');state['mode']='Revoked'
            else:self.fail('unexpected click')
        def progress():effect('barrier');budget.wait_render_progress()
        def key(op,a,b):effect('key');budget._command(op,a,b)
        flow.native.snapshot=snapshot;flow.observer.read.return_value=[]
        flow.native.capture_host=mock.Mock(return_value=(text,snapshot()['host_observation']))
        flow.controller.click.side_effect=click
        flow.controller.wait_render_progress.side_effect=progress
        flow.controller._preflight_ascii_batches.side_effect=budget._preflight_ascii_batches
        flow.controller._command.side_effect=key
        with mock.patch.object(F.time,'monotonic_ns',return_value=10_000_000_000):
            with self.assertRaises(F.C.Rejected) as error:flow.run()
        self.assertEqual(error.exception.code,'source_failure')
        self.assertTrue(state['seen_revoked'])
        self.assertEqual(flow.host_occurrences.attempts,3)
        self.assertEqual(flow.host_stage,'Storage')
        self.assertEqual(flow.startup_index,3 if after_submit else 2)
        self.assertEqual(flow.pending_host is None,after_submit)
        self.assertEqual(flow.host_rejection,None if after_submit else 'host_entry_changed')
        self.assertEqual(flow.controller.click.call_count,3 if after_submit else 1)
        self.assertEqual(len(self.fixture.secret_instances),1 if after_submit else 0)
        self.assertEqual(sum(x=='key' for x in state['effects']),68 if after_submit else 0)
        flow.native.capture_host.assert_called_once()
        flow.controller.observe.assert_not_called();flow.controller.type_ascii.assert_not_called()
        flow.controller.scroll_up.assert_not_called();flow.controller.scroll_down.assert_not_called()
        F.C.validate_host_diagnostic(dict(version=1,attempted_lines=3,startup_stage='Storage',category=flow.host_rejection or 'none'))

    def test_revoked_after_third_begin_before_typing_marks_pending_entry_boundary(self):
        self._run_revoked_third_host_boundary(False)

    def test_revoked_after_third_submit_return_preserves_no_pending_entry_category(self):
        self._run_revoked_third_host_boundary(True)

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
        self._actual_startup(False)
    def test_semantic_all13_actual_native_methods_without_ocr_or_capture(self):
        self._actual_startup(True)
    def _actual_startup(self,semantic):
        from unittest import mock
        import itertools,contextlib,io
        from test_ci_financial_input_batching import RecordingController,raw_event_count
        controller=mock.Mock();budget=RecordingController()
        if semantic:self.fixture.deadline_ns=time.monotonic_ns()+F.C.ORIGINAL_NS
        state=dict(mode='Idle',remaining=0,step=0,generation=0,line=None,submitted=[],captures=0,focus=0,
                   begin_boundary=0,submit_boundary=0,coverage=0)
        prompts=self.PROMPTS
        def text():return '\n'.join(prompts[:min(state['step']+1,13)])+(F.HOST_COMMANDS_INSTRUCTION if semantic and state['step']==13 else '')
        def crop():return (':' if state['coverage']==0 else 'directory (absolute): ') if state['step']==0 and state['coverage']<2 else text()
        class Observer:
            expected_profile=F.C.SEMANTIC_PROFILE if semantic else F.C.EXTERNAL_PROFILE
            def host_view(self,s):
                state['captures']+=1
                h=s['host_observation']
                view=dict(id=s['host_view_id'],view_generation=s['view_generation'],revision=h['revision'],nonws_end=h['nonws_end'],view=h['view'],text=crop())
                F.C.match_host_view(s,view)
                return view['text']
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
                h=dict(revision=min(state['step']+1,14 if semantic else 13),nonws_end=F.H.count(text()),context_valid=True,
                       entry=entry,editor=dict(ordinal=state['step']+1,revision=state['step']+1) if editing else None,
                       view=dict(rect=[10,200,110,220],nonws=F.H.count(crop()),rows=20) if not protected else None)
                result=observed_snapshot(phase='Selecting',owner=None,subphase='None',focused=True,
                    view_generation=state['generation'],secret_input=False,host_input=protected,host_observation=h,
                    pixels_per_point=1,viewport=[1280,800],widgets=[dict(tag=t,owner=None,rect=[10,y,110,y+20],enabled=True) for t,y in widgets])
                if semantic:result['host_view_id']=None if protected else 1+state['step']*3+state['coverage']
                return result
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
        clock=itertools.count(time.monotonic_ns(),100_000_000 if semantic else 2_000_000_000);output=io.StringIO()
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
        self.assertEqual(state['captures'],16 if semantic else 15);controller.focus.assert_not_called()
        if semantic:
            ocr.read.assert_not_called();controller.observe.assert_not_called()
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
        flow=F.FullFlow(controller,fixture,Observer(),None)
        return flow,controller,state
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


class SemanticHostObserverTests(unittest.TestCase):
    def setUp(self):
        import copy
        self.copy=copy.deepcopy
        self.temp=tempfile.TemporaryDirectory();self.directory=pathlib.Path(self.temp.name)
        self.o=O.ObserverFiles(self.directory,time.monotonic_ns()+10_000_000_000,O.C.SEMANTIC_PROFILE)
        self.text='Additional shared agreement IDs, comma-separated; blank for none: '
        n=sum(c not in ' \t\r\n\f\v' for c in self.text)
        self.view=dict(id=1,view_generation=1,revision=7,nonws_end=n,view=dict(rect=[10,10,600,230],nonws=n,rows=4),text=self.text)
        self.snapshot=dict(phase='Selecting',subphase='None',owner=None,view_generation=1,focused=True,secret_input=False,host_input=False,pixels_per_point=1,viewport=[1280,800],widgets=[dict(tag='HostOutput',owner=None,enabled=True,rect=[0,0,640,240])],host_observation=dict(revision=7,nonws_end=n,context_valid=True,entry='Idle',editor=None,view=self.copy(self.view['view'])),host_view_id=1)
    def tearDown(self):self.temp.cleanup()
    def record(self,kind,facts,sequence,role='Coordinator',profile=None):
        return dict(schema=1,profile=profile or O.C.SEMANTIC_PROFILE,role=role,sequence=sequence,elapsed_ns=0,kind=kind,facts=facts)
    def records(self):
        return [self.record('Birth',dict(pid=100,parent_pid=99,parent_role=None),1),self.record('HostRenderedView',self.copy(self.view),2),self.record('UiSnapshot',self.copy(self.snapshot),3)]
    def write(self,records):
        p=self.directory/'100.jsonl';p.write_text(''.join(json.dumps(r)+'\n' for r in records));p.chmod(0o600)
    def validate_join(self,records):
        for r in records:O.C.validate_record(r,O.C.SEMANTIC_PROFILE)
        self.o._join_host_views(records)
    def test_exact_private_record_join_no_text_in_snapshot(self):
        self.write(self.records());s=self.o.next_snapshot(self.o.deadline_ns)
        self.assertEqual(self.o.host_view(s),self.text);self.assertNotIn('text',s)
        self.assertEqual(len(self.o.read()),3) # proof sequence never filtered
    def test_old_profiles_reject_new_kind_and_snapshot_key(self):
        for profile in (O.C.PROFILE,O.C.EXTERNAL_PROFILE):
            for r in self.records()[1:]:
                r['profile']=profile
                with self.assertRaises(O.C.Rejected):O.C.validate_record(r,profile)
        with self.assertRaises(O.C.Rejected):O.C.validate_snapshot(self.snapshot)
    def test_missing_forward_duplicate_and_stale_refs_reject(self):
        records=self.records()
        variants=[records[:1]+records[2:],records[:1]+[records[2],records[1]],records+[records[1]],records+[self.record('UiSnapshot',self.snapshot|{'host_view_id':2,'view_generation':2},4)]]
        for variant in variants:
            with self.subTest(case=variants.index(variant)),self.assertRaises(O.C.Rejected):self.validate_join(variant)
    def test_partial_pair_is_not_usable_then_joins(self):
        records=self.records();self.write(records[:2]);self.o.read()
        with self.assertRaises(O.C.Rejected):self.o.host_view(self.snapshot)
        self.write(records);self.assertEqual(self.o.next_snapshot(self.o.deadline_ns),self.snapshot)
        self.assertEqual(self.o.host_view(self.snapshot),self.text)
    def test_all_metadata_mismatches_fail_closed(self):
        for key,value in (('revision',8),('nonws_end',self.view['nonws_end']+1),('view_generation',2),('id',2),('text',self.text+'x')):
            records=self.records();records[1]['facts'][key]=value
            with self.subTest(key=key),self.assertRaises(O.C.Rejected):self.validate_join(records)
        for key,value in (('rows',5),('rect',[11,10,600,230])):
            records=self.records();records[1]['facts']['view'][key]=value
            with self.assertRaises(O.C.Rejected):self.validate_join(records)
    def test_null_protected_clears_mutable_cache_and_reentry_needs_new_id(self):
        records=self.records();self.validate_join(records);old=self.o._semantic_active['text']
        s=self.copy(self.snapshot);s.update(host_view_id=None,view_generation=2,host_input=True)
        s['host_observation'].update(entry='Writing',view=None)
        records.append(self.record('UiSnapshot',s,4));self.validate_join(records)
        self.assertTrue(old and not any(old));self.assertIsNone(self.o._semantic_active)
        with self.assertRaises(O.C.Rejected):self.o.host_view(self.snapshot)
        with self.assertRaises(O.C.Rejected):self.validate_join(records+[self.record('UiSnapshot',self.snapshot|{'view_generation':3},5)])
        v=self.copy(self.view);v.update(id=2,view_generation=3)
        self.validate_join(records+[self.record('HostRenderedView',v,5),self.record('UiSnapshot',self.snapshot|{'view_generation':3,'host_view_id':2},6)])
        self.assertEqual(self.o.host_view(self.snapshot|{'view_generation':3,'host_view_id':2}),self.text)
    def test_native_lf_row_bound_is_identical(self):
        view=self.copy(self.view);view['text']=self.text+'\n'*4
        with self.assertRaises(O.C.Rejected):O.C.validate_host_rendered_view(view)
        view['text']=self.text+'\n'*3;O.C.validate_host_rendered_view(view)
    def test_bad_role_bytes_budget_and_extra_fields_reject_without_text_exception(self):
        for value in ('private-sentinel\x00','private-sentinel\t','private-sentinelé','x'*8193,''):
            v=self.copy(self.view);v['text']=value
            with self.assertRaises(O.C.Rejected) as error:O.C.validate_host_rendered_view(v)
            self.assertNotIn('private-sentinel',str(error.exception))
        for key,value in (('id',513),('id',True),('unexpected','private-sentinel')):
            v=self.copy(self.view);v[key]=value
            with self.assertRaises(O.C.Rejected):O.C.validate_host_rendered_view(v)
        with self.assertRaises(O.C.Rejected):O.C.validate_record(self.record('HostRenderedView',self.view,1,role='Host'),O.C.SEMANTIC_PROFILE)
    def test_identical_new_id_after_unobserved_hidden_pass_does_not_renew_occurrence(self):
        records=self.records();self.validate_join(records+[self.record('UiSnapshot',self.snapshot|{'view_generation':2},4)])
        v=self.copy(self.view);v.update(id=2,view_generation=2)
        self.validate_join(records+[self.record('HostRenderedView',v,4),self.record('UiSnapshot',self.snapshot|{'host_view_id':2,'view_generation':2},5)])
        ledger=F.H.HostOccurrences();occurrence,_=ledger.inspect(self.text,self.snapshot['host_observation']);ledger.latch(occurrence)
        with self.assertRaises(F.H.HostContextRejected):ledger.inspect(self.o.host_view(self.snapshot|{'host_view_id':2,'view_generation':2}),self.snapshot['host_observation'])
        v['revision']=8;s=self.copy(self.snapshot);s.update(host_view_id=2,view_generation=2);s['host_observation']['revision']=8
        self.validate_join(records+[self.record('HostRenderedView',v,4),self.record('UiSnapshot',s,5)])

    def test_final_requires_paired_view_and_no_unpaired_tail(self):
        records=self.records()
        with self.assertRaises(O.C.Rejected):O.C.join_host_views(records[:1],final=True)
        with self.assertRaises(O.C.Rejected):O.C.join_host_views(records[:2],final=True)
        O.C.join_host_views(records,final=True)
        new=self.copy(self.view);new.update(id=2,view_generation=2,revision=8)
        with self.assertRaises(O.C.Rejected):O.C.join_host_views(records+[self.record('HostRenderedView',new,4)],final=True)

class SemanticStartupCeilingTests(unittest.TestCase):
    def test_blocked_controller_read_uses_subordinate_timeout_and_original_clocks(self):
        from unittest import mock
        import socket
        now=[1_000_000_000];bound=now[0]+20_000_000
        transport=mock.Mock()
        def receive(*args):now[0]+=20_000_000;raise socket.timeout()
        transport.recvmsg.side_effect=receive
        controller=K.Controller(transport,now[0]+900_000_000_000,now[0]+900_000_000_000,_clock=lambda:now[0])
        originals=(controller.original_deadline_ns,controller.session_deadline_ns)
        controller.install_wait_ceiling(lambda:bound)
        with self.assertRaises(K.Rejected) as error:controller.wait_ready()
        self.assertEqual(error.exception.code,'deadline');transport.settimeout.assert_called_once_with(.02)
        transport.close.assert_called_once();transport.send.assert_not_called()
        self.assertEqual((controller.original_deadline_ns,controller.session_deadline_ns),originals)
    def test_ceiling_installed_once_invalid_bounds_and_legacy_deadline(self):
        from unittest import mock
        for value in (True,False,0,-1,'120',1.5):
            c=K.Controller(mock.Mock(),1000,1000,_clock=lambda:1);c.install_wait_ceiling(lambda:value)
            with self.assertRaises(K.Rejected):c._remaining()
        c=K.Controller(mock.Mock(),1000,1000,_clock=lambda:1)
        self.assertEqual(c._remaining(),999/1e9)
        c.install_wait_ceiling(lambda:None);self.assertEqual(c._remaining(),999/1e9)
        with self.assertRaises(K.Rejected):c.install_wait_ceiling(lambda:9999)
    def test_native_snapshot_passes_bound_to_actual_blocked_observer_loop(self):
        from unittest import mock
        now=[1_000_000_000];bound=now[0]+20_000_000
        with tempfile.TemporaryDirectory() as temp:
            observer=O.ObserverFiles(temp,now[0]+900_000_000_000,O.C.SEMANTIC_PROFILE)
            observer.read=mock.Mock(return_value=[])
            fixture=mock.Mock(deadline_ns=observer.deadline_ns);controller=mock.Mock()
            native=F.S.NativeScenario(controller,fixture,observer.next_snapshot,expected_profile=F.C.SEMANTIC_PROFILE,host_view=observer.host_view,wait_ceiling=lambda:bound)
            with mock.patch.object(O.time,'monotonic_ns',side_effect=lambda:now[0]),mock.patch.object(O.time,'sleep',side_effect=lambda _:now.__setitem__(0,now[0]+10_000_000)):
                with self.assertRaises(O.C.Rejected) as error:native.snapshot()
            self.assertEqual(error.exception.code,'deadline');self.assertEqual(now[0],bound)
            controller.assert_not_called();self.assertEqual(controller.mock_calls,[])
    def test_slot_not_renewed_by_observation_and_final_writing_retains_bound(self):
        from unittest import mock
        now=[1_000_000_000];fixture=mock.Mock(deadline_ns=900_000_000_000)
        observer=mock.Mock(expected_profile=F.C.SEMANTIC_PROFILE);controller=mock.Mock()
        with mock.patch.object(F.time,'monotonic_ns',side_effect=lambda:now[0]):
            flow=F.FullFlow(controller,fixture,observer,None);first=flow.startup_wait_ceiling()
            self.assertEqual(first,now[0]+F.C.ACTION_NS)
            for i in range(5):
                now[0]+=1_000_000_000
                flow.cache_host_observation(dict(entry='Idle',context_valid=True,revision=i,nonws_end=i,view=None))
                self.assertEqual(flow.startup_wait_ceiling(),first)
            flow.pending_startup=flow.startup_issued=0;flow.startup_submitted()
            second=flow.startup_wait_ceiling();self.assertGreater(second,first)
            self.assertEqual(second,now[0]+F.C.ACTION_NS)
            flow.startup_index=12;flow.pending_startup=flow.startup_issued=12
            flow.startup_submitted();self.assertEqual(flow.startup_wait_ceiling(),second)
            flow.pending_host=None
            writing=observed_snapshot(secret_input=False,host_input=True)
            self.assertTrue(flow.pump_host(writing));self.assertEqual(flow.startup_wait_ceiling(),second)
            self.assertFalse(flow.pump_host(observed_snapshot(focused=True,secret_input=False,host_input=False,widgets=[])))
            self.assertFalse(flow.host_startup_complete);self.assertEqual(flow.startup_wait_ceiling(),second)
            self.assertFalse(flow.startup_waiting) # Idle alone no longer proves commands consumption.
        old=F.FullFlow(mock.Mock(),mock.Mock(),mock.Mock(expected_profile=F.C.EXTERNAL_PROFILE),None)
        self.assertIsNone(old.startup_wait_ceiling())
        self.assertNotIn('_wait_ceiling_installed',old.controller.__dict__)

class HostReadOnlyTransitionTests(unittest.TestCase):
    def test_actual_run_configure_then_pretail_snapshot_does_not_fail_host_capture(self):
        from unittest import mock
        state=dict(clicked=False,pretail=0,generation=0,views=0)
        text='Native source opening pending.';n=F.H.count(text)
        class Observer:
            expected_profile=F.C.SEMANTIC_PROFILE
            def read(self):return []
            def host_view(self,s):state['views']+=1;return text
            def next_snapshot(self,deadline):
                state['generation']+=1
                if state['clicked'] and state['pretail']:
                    state['pretail']-=1;phase='Selecting'
                else:phase='V3Configuring' if state['clicked'] else 'Selecting'
                owner='Signer1' if phase=='V3Configuring' else None
                widgets=[dict(tag='HostOutput',owner=None,enabled=True,rect=[10,10,600,230]),dict(tag='BeginHostLine',owner=None,enabled=True,rect=[10,250,200,280])]
                if phase=='Selecting':widgets.append(dict(tag='ConfigureV3',owner='Signer1',enabled=True,rect=[10,300,200,330]))
                return dict(phase=phase,subphase='None',owner=owner,view_generation=state['generation'],focused=True,secret_input=False,host_input=False,pixels_per_point=1,viewport=[1280,800],widgets=widgets,host_view_id=1,host_observation=dict(revision=15 if state['clicked'] else 14,nonws_end=n,context_valid=True,entry='Idle',editor=None,view=dict(rect=[10,10,600,230],nonws=n,rows=1)))
        fixture=mock.Mock(deadline_ns=time.monotonic_ns()+F.C.ORIGINAL_NS)
        temp=tempfile.TemporaryDirectory();self.addCleanup(temp.cleanup)
        fixture.source_path.return_value=str(pathlib.Path(temp.name)/'not-created')
        controller=mock.Mock()
        def click(x,y):
            self.assertEqual((x,y),(105,315));state.update(clicked=True,pretail=1)
        controller.click.side_effect=click
        flow=F.FullFlow(controller,fixture,Observer(),mock.Mock())
        flow.startup_index=13;flow.startup_waiting=False;flow.startup_focus_seen=True
        flow.commands_instruction_observed=True;flow._startup_ceiling=None
        flow.host_ignored=(14,n,n) # Already inspected noninteractive pre-Configure tail.
        flow.host_lines=13;flow.host_stage='Commands'
        class SourceReached(Exception):pass
        fixture.form.side_effect=SourceReached()
        with self.assertRaises(SourceReached):flow.run()
        controller.click.assert_called_once();controller.type_ascii.assert_not_called();controller._command.assert_not_called()
        controller.observe.assert_not_called();flow.ocr.read.assert_not_called()
        fixture.form.assert_called_once_with('Signer1','v3')
        self.assertEqual(flow.host_lines,13);self.assertIsNone(flow.pending_host)
        self.assertEqual(flow.location,dict(phase='V3Configuring',subphase='None',owner='Signer1'))
        self.assertEqual(flow.actions,1)

    def capture_fixture(self,change_at=None,mutate=None,profile=None):
        import copy
        from unittest import mock
        profile=profile or F.C.SEMANTIC_PROFILE
        text='Native source opening pending.';n=F.H.count(text)
        frames=[]
        for i in range(1,7):
            s=dict(phase='Selecting',subphase='None',owner=None,view_generation=i,focused=True,secret_input=False,host_input=False,pixels_per_point=1,viewport=[1280,800],widgets=[dict(tag='HostOutput',owner=None,enabled=True,rect=[10,10,600,230])],host_observation=dict(revision=14,nonws_end=n,context_valid=True,entry='Idle',editor=None,view=dict(rect=[10,10,600,230],nonws=n,rows=1)))
            if profile==F.C.SEMANTIC_PROFILE:s['host_view_id']=1
            if change_at is not None and i>=change_at:s.update(phase='V3Configuring',owner='Signer1')
            if mutate is not None:mutate(s,i)
            frames.append(s)
        fixture=mock.Mock(deadline_ns=time.monotonic_ns()+F.C.ORIGINAL_NS)
        controller=mock.Mock();view=mock.Mock(return_value=text)
        native=F.S.NativeScenario(controller,fixture,mock.Mock(side_effect=copy.deepcopy(frames)),expected_profile=profile,host_view=view if profile==F.C.SEMANTIC_PROFILE else None)
        return native,controller,view
    def test_each_readonly_bracket_position_defers_without_effect_or_admitted_text(self):
        for position in range(1,7):
            with self.subTest(position=position):
                native,controller,view=self.capture_fixture(position)
                with self.assertRaises(F.S.HostObservationChanged):native.capture_host('Selecting',None,None)
                self.assertLessEqual(view.call_count,1)
                self.assertEqual(set(c[0] for c in controller.mock_calls),{'wait_render_progress'})
                self.assertEqual(native._used,set())
    def test_unsafe_later_frame_wins_over_earlier_transition(self):
        for unsafe in ('focus','host','secret','Revoked','Finished'):
            with self.subTest(unsafe=unsafe):
                def mutate(s,i):
                    if i!=2:return
                    s['host_view_id']=None;s['host_observation']['view']=None
                    if unsafe=='focus':s['focused']=False
                    elif unsafe=='host':s['host_input']=True;s['host_observation']['entry']='Writing'
                    elif unsafe=='secret':s['secret_input']=True
                    else:s.update(phase=unsafe,owner=None)
                native,controller,view=self.capture_fixture(1,mutate)
                with self.assertRaises(F.S.C.Rejected) as error:native.capture_host('Selecting',None,None)
                self.assertEqual(str(error.exception),'sensitive_capture' if unsafe in ('host','secret') else 'input_phase')
                view.assert_not_called();controller.click.assert_not_called();controller.observe.assert_not_called()
    def test_same_phase_unstable_layout_still_rejects(self):
        def mutate(s,i):
            if i==3:s['host_observation']['view']['rows']=2
        native,controller,view=self.capture_fixture(mutate=mutate)
        with self.assertRaises(F.S.C.Rejected) as error:native.capture_host('Selecting',None,None)
        self.assertEqual(str(error.exception),'snapshot');view.assert_not_called()
    def test_effectful_stable_and_legacy_capture_keep_strict_phase_guards(self):
        native,controller,view=self.capture_fixture(1)
        with self.assertRaises(F.S.C.Rejected) as error:native.stable('Selecting',None)
        self.assertEqual(str(error.exception),'input_phase');view.assert_not_called()
        native,controller,view=self.capture_fixture(1,profile=F.C.EXTERNAL_PROFILE)
        with self.assertRaises(F.S.C.Rejected) as error:native.capture_host('Selecting',None,None)
        self.assertEqual(str(error.exception),'input_phase');controller.observe.assert_not_called()
    def test_expired_capture_deadline_is_not_transition_deferral(self):
        native,controller,view=self.capture_fixture(1)
        native.wait_ceiling=lambda:time.monotonic_ns()-1
        with self.assertRaises(F.S.C.Rejected) as error:native.capture_host('Selecting',None,None)
        self.assertEqual(str(error.exception),'deadline')
        native.next_snapshot.assert_not_called();controller.assert_not_called();view.assert_not_called()

    def test_owner_only_readonly_transition_defers(self):
        def mutate(s,i):s.update(phase='Waiting',owner='Signer1' if i==1 else 'Signer2')
        native,controller,view=self.capture_fixture(mutate=mutate)
        with self.assertRaises(F.S.HostObservationChanged):native.capture_host('Waiting','Signer1',None)
        view.assert_not_called();controller.click.assert_not_called()
    def test_pending_host_context_mismatch_never_enters_readonly_deferral(self):
        from unittest import mock
        fixture=mock.Mock(deadline_ns=time.monotonic_ns()+F.C.ORIGINAL_NS)
        observer=mock.Mock(expected_profile=F.C.SEMANTIC_PROFILE)
        controller=mock.Mock();flow=F.FullFlow(controller,fixture,observer,None)
        flow.startup_index=13;flow.pending_host=('public','synthetic')
        flow.pending_occurrence=(0,8,1)
        s=dict(phase='Waiting',owner='Signer1',host_observation=dict(revision=2,nonws_end=9,context_valid=True,entry='Editing'))
        with mock.patch.object(flow.native,'capture_host') as capture:
            with self.assertRaises(F.C.Rejected) as error:flow.pump_host(s)
            self.assertEqual(str(error.exception),'input_phase');capture.assert_not_called()
        self.assertEqual(controller.mock_calls,[]);observer.host_view.assert_not_called()

class FormNavigationTests(unittest.TestCase):
    def test_actual_form_fill_seeks_clipped_submit_and_dispatches_once(self):
        from unittest import mock
        class Submitted(Exception):pass
        class Stalled(Exception):pass
        state=dict(generation=0,visible=False,submitted=False)
        class Observer:
            expected_profile=F.C.SEMANTIC_PROFILE
            def read(self):return []
            def host_view(self,s):raise AssertionError("No Host view admitted during this form test")
            def next_snapshot(self,deadline):
                if state['submitted']:raise Submitted()
                state['generation']+=1
                if state['generation']>120:raise Stalled()
                widgets=[dict(tag='ScrollRegion',owner=None,enabled=True,rect=[10,10,1270,790])]
                if not state['visible']:widgets.append(dict(tag='Field:V3Selection',owner='Signer1',enabled=True,rect=[10,500,1200,740]))
                if state['visible']:widgets.append(dict(tag='BeginV3',owner='Signer1',enabled=True,rect=[10,750,400,780]))
                return dict(phase='V3Configuring',subphase='None',owner='Signer1',view_generation=state['generation'],focused=True,secret_input=False,host_input=False,pixels_per_point=1,viewport=[1280,800],widgets=widgets,host_view_id=None,host_observation=dict(revision=1,nonws_end=0,context_valid=False,entry='Idle',editor=None,view=None))
        fixture=mock.Mock(deadline_ns=time.monotonic_ns()+F.C.ORIGINAL_NS)
        fixture.form.return_value={'V3Selection':'synthetic public selection'}
        controller=mock.Mock()
        def click(x,y):
            if (x,y)==(205,765):state['submitted']=True
            else:self.assertEqual((x,y),(605,620))
        controller.click.side_effect=click
        controller.scroll_down.side_effect=lambda *args:state.update(visible=True)
        flow=F.FullFlow(controller,fixture,Observer(),None)
        flow.startup_index=13;flow.startup_focus_seen=True;flow._startup_ceiling=None
        flow.commands_instruction_observed=True
        with self.assertRaises(Submitted):flow.run()
        controller.type_ascii.assert_called_once_with('synthetic public selection')
        controller.clear_field.assert_called_once();self.assertEqual(controller.click.call_count,2)
        self.assertEqual(controller.scroll_up.call_count,24);controller.scroll_down.assert_called_once()
        self.assertEqual(flow.actions,1);self.assertTrue(flow.used(dict(phase='V3Configuring',subphase='None'),'BeginV3','Signer1'))
        controller.observe.assert_not_called()
    def test_form_navigation_respects_consumed_disabled_incomplete_and_protected_states(self):
        from unittest import mock
        for case in ('consumed','disabled','incomplete','host_protected','secret_protected'):
            with self.subTest(case=case):
                class End(Exception):pass
                state=dict(generation=0)
                class Observer:
                    expected_profile=F.C.SEMANTIC_PROFILE
                    def read(self):return []
                    def host_view(self,s):raise AssertionError('unexpected Host capture')
                    def next_snapshot(self,deadline):
                        state['generation']+=1
                        if state['generation']>3:raise End()
                        widgets=[dict(tag='ScrollRegion',owner=None,enabled=True,rect=[10,10,1270,790])]
                        if case=='disabled':widgets.append(dict(tag='BeginV3',owner='Signer1',enabled=False,rect=[10,750,400,780]))
                        return dict(phase='V3Configuring',subphase='None',owner='Signer1',view_generation=state['generation'],focused=True,secret_input=case=='secret_protected',host_input=case=='host_protected',pixels_per_point=1,viewport=[1280,800],widgets=widgets,host_view_id=None,host_observation=dict(revision=1,nonws_end=0,context_valid=False,entry='Writing' if case=='host_protected' else 'Idle',editor=None,view=None))
                fixture=mock.Mock(deadline_ns=time.monotonic_ns()+F.C.ORIGINAL_NS)
                fixture.form.return_value={'V3Selection':'synthetic public selection'}
                controller=mock.Mock();flow=F.FullFlow(controller,fixture,Observer(),None)
                flow.startup_index=13;flow.startup_focus_seen=True;flow._startup_ceiling=None
                flow.commands_instruction_observed=True
                if case!='incomplete':flow.filled.add(('V3Configuring','Field:V3Selection','Signer1'))
                if case=='consumed':flow.done.add(('V3Configuring','None','BeginV3','Signer1',None))
                with mock.patch.object(flow,'seek',wraps=flow.seek) as seek:
                    with self.assertRaises(F.C.Rejected if case=='secret_protected' else End):flow.run()
                    tags=[call.args[1] for call in seek.call_args_list]
                self.assertEqual(tags,['Field:V3Selection']*3 if case=='incomplete' else ['BeginV3']*3 if case=='disabled' else [])
                controller.click.assert_not_called();controller.type_ascii.assert_not_called();controller.clear_field.assert_not_called();controller.observe.assert_not_called()
                if case!='incomplete':controller.scroll_up.assert_not_called();controller.scroll_down.assert_not_called()
                if case=='host_protected':self.assertEqual(controller.wait_render_progress.call_count,3)
    def test_permanently_hidden_form_action_exhausts_original_seek_bound(self):
        from unittest import mock
        state=dict(generation=0)
        observer=mock.Mock(expected_profile=F.C.SEMANTIC_PROFILE);observer.read.return_value=[]
        def snapshot(deadline):
            state['generation']+=1
            return dict(phase='V3Configuring',subphase='None',owner='Signer1',view_generation=state['generation'],focused=True,secret_input=False,host_input=False,pixels_per_point=1,viewport=[1280,800],widgets=[dict(tag='ScrollRegion',owner=None,enabled=True,rect=[10,10,1270,790])],host_view_id=None,host_observation=dict(revision=1,nonws_end=0,context_valid=False,entry='Idle',editor=None,view=None))
        observer.next_snapshot.side_effect=snapshot
        fixture=mock.Mock(deadline_ns=time.monotonic_ns()+F.C.ORIGINAL_NS)
        fixture.form.return_value={'V3Selection':'synthetic public selection'}
        controller=mock.Mock();flow=F.FullFlow(controller,fixture,observer,None)
        flow.startup_index=13;flow.startup_focus_seen=True;flow._startup_ceiling=None
        flow.commands_instruction_observed=True
        flow.filled.add(('V3Configuring','Field:V3Selection','Signer1'))
        original_deadline=fixture.deadline_ns
        with self.assertRaises(F.C.Rejected) as error:flow.run()
        self.assertEqual(str(error.exception),'input_widget')
        self.assertEqual(controller.scroll_up.call_count,24);self.assertEqual(controller.scroll_down.call_count,40)
        self.assertEqual(state['generation'],65);self.assertEqual(flow.actions,0)
        self.assertIsNone(flow._startup_ceiling);self.assertEqual(fixture.deadline_ns,original_deadline)
        controller.click.assert_not_called();controller.type_ascii.assert_not_called();controller.clear_field.assert_not_called();controller.observe.assert_not_called();observer.host_view.assert_not_called()

class NativeFailureBoundaryTests(unittest.TestCase):
    def facts(self,**changes):
        value=dict(version=1,ui='FocusLost',driver='Unobserved',transport='Unobserved',core='Unobserved');value.update(changes);return value
    def record(self,facts=None,sequence=2,**changes):
        value=dict(schema=1,profile=F.C.SEMANTIC_PROFILE,role='Coordinator',sequence=sequence,elapsed_ns=sequence,kind='NativeFailureBoundary',facts=self.facts() if facts is None else facts);value.update(changes);return value
    def birth(self):return self.record(dict(pid=100,parent_pid=99,parent_role=None),sequence=1,kind='Birth')
    def chain(self):
        rows=[self.birth()];facts=self.facts()
        for name,code in [('ui','FocusLost'),('driver','WorkErrorUnclassified'),('transport','RestrictedObserved'),('core','AlreadyClosedObserved')]:
            facts=dict(facts,**{name:code});rows.append(self.record(facts,len(rows)+1))
        return rows
    def test_exact_codes_and_ui_or_driver_gate(self):
        for component,codes in F.C.NATIVE_FAILURE_CODES.items():
            for code in codes:
                facts=self.facts(**{component:code})
                if component=='ui' and code=='Unobserved':facts['driver']='WorkErrorUnclassified'
                F.C.validate_record(self.record(facts),F.C.SEMANTIC_PROFILE)
        for extra in ({},{'core':'SessionExpired'},{'transport':'PtyOutputEof'},{'core':'PeerProcessExit','transport':'RestrictedObserved'}):
            with self.assertRaises(F.C.Rejected):F.C.validate_record(self.record(self.facts(ui='Unobserved',**extra)),F.C.SEMANTIC_PROFILE)
    def test_strict_keys_types_roles_profiles_and_no_arbitrary_strings(self):
        import copy
        cases=[]
        for key,value in [('version',True),('version',2),('ui','/synthetic/private/path'),('driver','FocusLost'),('driver',None),('transport',[]),('core',1)]:
            f=self.facts();f[key]=value;cases.append(self.record(f))
        for key in self.facts():
            f=self.facts();del f[key];cases.append(self.record(f))
        f=self.facts();f['error']='private detail';cases.append(self.record(f))
        cases.extend(self.record(role=role) for role in F.C.ROLES if role!='Coordinator')
        for record in cases:
            with self.assertRaises(F.C.Rejected):F.C.validate_record(record,F.C.SEMANTIC_PROFILE)
        for profile in (F.C.PROFILE,F.C.EXTERNAL_PROFILE):
            with self.assertRaises(F.C.Rejected):F.C.validate_record(self.record(profile=profile),profile)
    def test_monotone_four_aggregates_and_unavailable_absence(self):
        rows=self.chain();latest=F.C.native_failure_sequence(rows,F.C.SEMANTIC_PROFILE)
        self.assertEqual(latest,rows[-1]['facts'])
        self.assertEqual(F.C.cached_native_failure_diagnostic(rows,F.C.SEMANTIC_PROFILE)['availability'],'Observed')
        for rows in ([],[self.birth()]):
            value=F.C.cached_native_failure_diagnostic(rows,F.C.SEMANTIC_PROFILE)
            self.assertEqual(value['availability'],'Unavailable')
            self.assertTrue(all(value[k]=='Unobserved' for k in F.C.NATIVE_FAILURE_COMPONENTS))
    def test_duplicate_rewrite_reset_order_and_fifth_record_rejected(self):
        import copy
        cases=[]
        r=self.chain();r[2]['facts']=dict(r[1]['facts']);cases.append(r)
        r=self.chain();r[2]['facts']['ui']='Escape';cases.append(r)
        r=self.chain();r[2]['facts']['ui']='Unobserved';cases.append(r)
        r=self.chain();r[2]['sequence']=1;cases.append(r)
        r=self.chain();r[2]['elapsed_ns']=0;cases.append(r)
        r=self.chain();r[0]=self.record(sequence=1);cases.append(r)
        r=self.chain();r.append(self.record(dict(r[-1]['facts']),6));cases.append(r)
        for rows in cases:
            with self.assertRaises(F.C.Rejected):F.C.native_failure_sequence(rows,F.C.SEMANTIC_PROFILE)
    def test_private_observer_lineage_partial_flush_and_immutable_history(self):
        with tempfile.TemporaryDirectory() as temp:
            root=pathlib.Path(temp);p=root/'100.jsonl'
            encode=lambda r:json.dumps(r).encode()+b'\n'
            first=encode(self.birth());boundary=encode(self.record())
            p.write_bytes(first+boundary[:-3]);p.chmod(0o600)
            observer=O.ObserverFiles(root,time.monotonic_ns()+10_000_000_000,expected_profile=F.C.SEMANTIC_PROFILE)
            rows=observer.read();self.assertEqual(len(rows),1)
            self.assertEqual(O.C.cached_native_failure_diagnostic(rows,F.C.SEMANTIC_PROFILE)['availability'],'Unavailable')
            with p.open('ab') as stream:stream.write(boundary[-3:])
            self.assertEqual(O.C.cached_native_failure_diagnostic(observer.read(),F.C.SEMANTIC_PROFILE)['availability'],'Observed')
            self.assertEqual(observer.read(),observer.read()) # rereading unchanged bytes is not a new native record.
            with p.open('ab') as stream:stream.write(encode(self.record(sequence=3)))
            with self.assertRaises(O.C.Rejected):observer.read()
    def test_projection_strict_unavailable_and_no_private_values(self):
        value=F.C.cached_native_failure_diagnostic([],F.C.SEMANTIC_PROFILE)
        for change in ({'availability':'Observed'},{'availability':'unknown'},{'ui':'FocusLost'},{'version':True},{'path':'private'}):
            bad=dict(value,**change)
            with self.assertRaises(F.C.Rejected):F.C.validate_native_failure_diagnostic(bad)
        for key in value:
            bad=dict(value);del bad[key]
            with self.assertRaises(F.C.Rejected):F.C.validate_native_failure_diagnostic(bad)
    def test_failure_emitter_cached_only_legacy_silent_and_print_failure_safe(self):
        import io,contextlib
        from unittest import mock
        container=F.load('ci-financial-container')
        flow=mock.Mock(expected_profile=F.C.SEMANTIC_PROFILE,records=self.chain())
        flow.observer.failure_diagnostics.return_value={'native':F.C.cached_native_failure_diagnostic(self.chain(),F.C.SEMANTIC_PROFILE)}
        flow.snapshot.side_effect=AssertionError('no fresh observation');flow.observer.read.side_effect=AssertionError('no private read')
        output=io.StringIO()
        with contextlib.redirect_stdout(output):container.emit_cached_native_failure(flow)
        line=output.getvalue();self.assertTrue(line.startswith('CI_FINANCIAL_NATIVE_FAILURE_DIAGNOSTIC '))
        self.assertNotIn('pid',line);self.assertNotIn('elapsed',line);self.assertNotIn('sequence',line)
        flow.snapshot.assert_not_called();flow.observer.read.assert_not_called()
        with mock.patch('builtins.print',side_effect=BrokenPipeError):container.emit_cached_native_failure(flow)
        for profile in (F.C.PROFILE,F.C.EXTERNAL_PROFILE):
            flow.expected_profile=profile
            with mock.patch('builtins.print') as emit:container.emit_cached_native_failure(flow)
            emit.assert_not_called()
    def test_supervisor_failure_only_duplicate_late_and_legacy_rejection(self):
        import io,contextlib
        supervisor=F.load('ci-financial-supervisor');profile=F.C.SEMANTIC_PROFILE
        value=F.C.cached_native_failure_diagnostic(self.chain(),profile)
        line=b'CI_FINANCIAL_NATIVE_FAILURE_DIAGNOSTIC '+json.dumps(value).encode()
        records=supervisor.RuntimeRecords('external',profile);output=io.StringIO()
        with contextlib.redirect_stdout(output):records(line)
        self.assertEqual(output.getvalue(),'')
        with self.assertRaises(supervisor.Failure):records(line)
        with contextlib.redirect_stdout(output):records(b'CI_FINANCIAL_RESULT '+json.dumps(supervisor.P.failure('normal_finish',profile)).encode())
        self.assertIn('NATIVE_FAILURE_DIAGNOSTIC',output.getvalue())
        with self.assertRaises(supervisor.Failure):records(line)
        records=supervisor.RuntimeRecords('external',profile);records(line)
        candidate=dict(schema=1,profile=profile,native_oracle_verified=True,fixture_cleaned=True,display_cleaned=True,public_chain_verified=False,dispatch_attempted=False)
        with self.assertRaises(supervisor.Failure):records(b'CI_FINANCIAL_CANDIDATE '+json.dumps(candidate).encode())
        with self.assertRaises(supervisor.Failure):supervisor.RuntimeRecords('external')(line)
    def test_native_failure_forbids_close_even_with_all_normal_milestones(self):
        from unittest import mock
        controller=mock.Mock();fixture=mock.Mock(deadline_ns=time.monotonic_ns()+F.C.ORIGINAL_NS)
        native=F.S.NativeScenario(controller,fixture,mock.Mock(),expected_profile=F.C.SEMANTIC_PROFILE,host_view=mock.Mock())
        records=[self.record({},i+1,kind=k) for i,k in enumerate(F.C.NORMAL_DIAGNOSTIC_STEPS)]+[self.record(sequence=5)]
        with self.assertRaises(F.S.C.Rejected) as error:native.close_after_normal_proof(records,None,F.C.SEMANTIC_PROFILE)
        self.assertEqual(str(error.exception),'observer_failure');controller.terminal_click.assert_not_called();native.next_snapshot.assert_not_called()
    def test_complete_semantic_oracle_still_requires_normal_proof_and_rejects_boundary(self):
        from test_ci_financial_semantic_routing import semantic_case,O as oracle
        records,external=semantic_case();oracle.validate_completed(records,100,0,external,oracle.C.SEMANTIC_PROFILE)
        sequence=max(r['sequence'] for r in records if r['role']=='Coordinator')+1
        elapsed=max(r['elapsed_ns'] for r in records)+1
        records.append(self.record(sequence=sequence,elapsed_ns=elapsed))
        with self.assertRaises(oracle.C.Rejected) as error:oracle.validate_completed(records,100,0,external,oracle.C.SEMANTIC_PROFILE)
        self.assertEqual(str(error.exception),'observer_failure')
    def test_actual_terminal_snapshot_retains_boundary_for_cached_failure_reporting(self):
        import io,contextlib
        from unittest import mock
        with tempfile.TemporaryDirectory() as temp:
            root=pathlib.Path(temp);p=root/'100.jsonl'
            snapshot=dict(phase='Finished',subphase='None',owner=None,view_generation=1,focused=True,secret_input=False,host_input=False,pixels_per_point=1,viewport=[1280,800],widgets=[],host_view_id=None,host_observation=dict(revision=1,nonws_end=0,context_valid=False,entry='Closed',editor=None,view=None))
            rows=[self.birth(),self.record(),self.record(snapshot,sequence=3,kind='UiSnapshot')]
            p.write_bytes(b''.join(json.dumps(r).encode()+b'\n' for r in rows));p.chmod(0o600)
            deadline=time.monotonic_ns()+10_000_000_000
            observer=O.ObserverFiles(root,deadline,expected_profile=F.C.SEMANTIC_PROFILE)
            fixture=mock.Mock(deadline_ns=deadline);controller=mock.Mock()
            flow=F.FullFlow(controller,fixture,observer,None)
            with self.assertRaises(O.C.Rejected) as error:flow.run()
            self.assertEqual(str(error.exception),'observer_failure');self.assertEqual(flow.records,[])
            self.assertEqual(observer.failure_diagnostics()['native']['availability'],'Observed')
            container=F.load('ci-financial-container');output=io.StringIO()
            with mock.patch.object(observer,'read',side_effect=AssertionError('fresh IO during failure')):
                with contextlib.redirect_stdout(output):container.emit_cached_native_failure(flow)
            self.assertIn('"availability":"Observed"',output.getvalue())
            controller.terminal_click.assert_not_called();controller.click.assert_not_called();controller.observe.assert_not_called()
    def test_prior_outer_cleanup_success_does_not_suppress_runtime_failure_diagnostic(self):
        import io,contextlib
        supervisor=F.load('ci-financial-supervisor');profile=F.C.SEMANTIC_PROFILE
        value=F.C.cached_native_failure_diagnostic([],profile)
        output=io.StringIO()
        with contextlib.redirect_stdout(output):
            # The supervisor's earlier independent cleanup/preflight result is
            # an outer marker, never an input to the later container parser.
            supervisor.emit('RESULT',dict(passed=True,cleanup_only=True))
            runtime=supervisor.RuntimeRecords('external',profile)
            runtime(b'CI_FINANCIAL_NATIVE_FAILURE_DIAGNOSTIC '+json.dumps(value).encode())
            runtime(b'CI_FINANCIAL_RESULT '+json.dumps(supervisor.P.failure('normal_finish',profile)).encode())
        self.assertEqual(runtime.finish(1)['code'],'normal_finish')
        lines=output.getvalue().splitlines()
        self.assertEqual(len(lines),3)
        self.assertIn('"passed":true',lines[0])
        self.assertTrue(lines[1].startswith('CI_FINANCIAL_NATIVE_FAILURE_DIAGNOSTIC '))
        self.assertTrue(lines[2].startswith('CI_FINANCIAL_FAILURE '))

class CommandsConsumptionGateTests(unittest.TestCase):
    def harness(self,*,ack_after=2,marker=None,clock=None,crop='full'):
        from unittest import mock
        marker=F.HOST_COMMANDS_INSTRUCTION if marker is None else marker
        prompt=HostStartupContractTests.PROMPTS[-1]
        state=dict(ack=False,waits=0,configured=False,generation=0,captures=0,observations=0,crop=crop)
        frontier=F.H.count(prompt)
        class ReachedSource(Exception):pass
        class Observer:
            expected_profile=F.C.SEMANTIC_PROFILE
            def read(self):
                state['observations']+=1
                # Publish between outer observations, never inside the stable
                # capture bracket. Mid-bracket publication must still reject.
                if ack_after is not None and state['observations']>ack_after:state['ack']=True
                return []
            def next_snapshot(self,deadline):
                if clock is not None:F.C.require(clock[0]<deadline,'deadline')
                state['generation']+=1
                text=prompt+(marker if state['ack'] else '')
                h=dict(revision=14 if state['ack'] else 13,nonws_end=F.H.count(text),context_valid=True,
                       entry='Idle',editor=None,view=(None if state['crop']=='none' else dict(rect=[10,10,600,230],nonws=F.H.count(text[-14:] if state['crop']=='partial' else text),rows=4)))
                return dict(phase='V3Configuring' if state['configured'] else 'Selecting',subphase='None',
                    owner='Signer1' if state['configured'] else None,view_generation=state['generation'],focused=True,
                    secret_input=False,host_input=False,pixels_per_point=1,viewport=[1280,800],
                    host_view_id=None if state['crop']=='none' else (2 if state['ack'] else 1)+(1 if state['crop']=='partial' else 0),host_observation=h,widgets=[
                        dict(tag='ScrollRegion',owner=None,enabled=True,rect=[0,0,1280,790]),
                        dict(tag='HostOutput',owner=None,enabled=True,rect=[0,0,640,240]),
                        dict(tag='BeginHostLine',owner=None,enabled=True,rect=[10,250,200,280]),
                        dict(tag='ConfigureV3',owner='Signer1',enabled=True,rect=[10,300,200,330])])
            def host_view(self,s):
                state['captures']+=1;text=prompt+(marker if state['ack'] else '')
                if state['crop']=='partial':text=text[-14:]
                h=s['host_observation']
                F.C.match_host_view(s,dict(id=s['host_view_id'],view_generation=s['view_generation'],
                    revision=h['revision'],nonws_end=h['nonws_end'],view=h['view'],text=text))
                return text
        now=time.monotonic_ns();fixture=mock.Mock(deadline_ns=now+F.C.ORIGINAL_NS)
        temp=tempfile.TemporaryDirectory();self.addCleanup(temp.cleanup)
        fixture.source_path.return_value=str(pathlib.Path(temp.name)/'not-created')
        fixture.form.side_effect=ReachedSource()
        controller=mock.Mock()
        def progress():
            state['waits']+=1
            if clock is not None:clock[0]+=1_000_000_000
        def click(x,y):
            self.assertTrue(state['ack'],'Source input must wait for actual native message')
            self.assertEqual((x,y),(105,315));self.assertFalse(state['configured']);state['configured']=True
        controller.wait_render_progress.side_effect=progress;controller.click.side_effect=click
        observer=Observer();flow=F.FullFlow(controller,fixture,observer,None)
        flow.startup_index=13;flow.startup_waiting=True;flow.startup_focus_seen=True
        flow.host_lines=13;flow.host_stage='Commands';flow.ocr_delay=0
        flow.host_occurrences.frontier=frontier;flow.host_occurrences.last_end=frontier;flow.host_occurrences.last_revision=13
        return flow,state,controller,observer,ReachedSource
    def test_actual_run_waits_for_new_rendered_message_then_configures_once(self):
        flow,state,c,o,stop=self.harness()
        bound=flow.startup_wait_ceiling();frontier=flow.host_occurrences.frontier
        with self.assertRaises(stop):flow.run()
        self.assertGreaterEqual(state['waits'],2);self.assertEqual(state['captures'],3)
        self.assertTrue(flow.commands_instruction_observed);self.assertTrue(flow.host_startup_complete)
        self.assertEqual(flow.host_stage,'Operational');self.assertEqual(flow.host_capture_outcome,'Accepted')
        self.assertEqual(flow.host_occurrences.frontier,frontier);self.assertEqual(flow.host_lines,13)
        self.assertIsNone(flow.startup_wait_ceiling());self.assertGreater(bound,0)
        c.click.assert_called_once();c.type_ascii.assert_not_called();c._command.assert_not_called();c.observe.assert_not_called()
        self.assertEqual(flow.location['phase'],'V3Configuring')
    def test_missing_message_expires_original_final_slot_without_source_action(self):
        from unittest import mock
        clock=[1_000_000_000]
        with mock.patch.object(F.time,'monotonic_ns',side_effect=lambda:clock[0]):
            flow,state,c,o,_=self.harness(ack_after=None,clock=clock)
            bound=flow.startup_wait_ceiling()
            with self.assertRaises(F.C.Rejected) as e:flow.run()
        self.assertEqual(str(e.exception),'deadline');self.assertEqual(flow.startup_wait_ceiling(),bound)
        self.assertFalse(flow.commands_instruction_observed);self.assertFalse(flow.startup_waiting)
        self.assertEqual(flow.host_stage,'Commands');self.assertEqual(flow.host_lines,13)
        c.click.assert_not_called();c.type_ascii.assert_not_called();c._command.assert_not_called();c.observe.assert_not_called()
    def test_exact_marker_and_native_source_order_no_normalization(self):
        from unittest import mock
        source=(ROOT.parent/'crates/wholepact-native-host/src/host/financial/retained_foreground_v1.rs').read_text()
        self.assertIn('terminal.message("'+F.HOST_COMMANDS_INSTRUCTION.replace('\n','\\n')+'")?',source)
        self.assertLess(source.index('let commands = read_selection'),source.index('Select original reviewer 1 of 2'))
        self.assertLess(source.index('Select original reviewer 1 of 2'),source.index('let endpoint = wait_original_coordinated_pair_endpoint'))
        for marker in (F.HOST_COMMANDS_INSTRUCTION[:-1],F.HOST_COMMANDS_INSTRUCTION.replace('reviewer 1','reviewer 2'),
                       F.HOST_COMMANDS_INSTRUCTION.replace('original reviewer','original\nreviewer'),F.HOST_COMMANDS_INSTRUCTION+'extra'):
            flow,state,c,o,_=self.harness(marker=marker);state['ack']=True;flow.startup_waiting=False
            bound=flow.startup_wait_ceiling()
            self.assertFalse(flow.observe_commands_instruction(o.next_snapshot(bound)))
            self.assertFalse(flow.commands_instruction_observed);self.assertEqual(flow.startup_wait_ceiling(),bound)
            c.click.assert_not_called();c._command.assert_not_called()
    def test_stale_span_focus_protection_and_context_guards_remain_closed(self):
        from unittest import mock
        for change in ('stale','focus','secret','host','context'):
            with self.subTest(change=change):
                flow,state,c,o,_=self.harness();state['ack']=True;flow.startup_waiting=False
                s=o.next_snapshot(flow.startup_wait_ceiling())
                if change=='stale':flow.host_occurrences.frontier=s['host_observation']['nonws_end']
                elif change=='context':s['host_observation']['context_valid']=False
                else:s[{'focus':'focused','secret':'secret_input','host':'host_input'}[change]]=change!='focus'
                if change=='context':self.assertFalse(flow.observe_commands_instruction(s))
                else:
                    with self.assertRaises(F.C.Rejected):flow.observe_commands_instruction(s)
                self.assertFalse(flow.commands_instruction_observed);c.click.assert_not_called();c.observe.assert_not_called()
                if change!='stale':self.assertEqual(state['captures'],0)
    def test_writing_hold_and_expired_after_capture_never_clear_ceiling(self):
        from unittest import mock
        flow,state,c,o,_=self.harness();bound=flow.startup_wait_ceiling()
        s=o.next_snapshot(bound);s['host_input']=True;s['host_observation'].update(entry='Writing',view=None)
        self.assertTrue(flow.pump_host(s));self.assertEqual(state['captures'],0);self.assertEqual(flow.startup_wait_ceiling(),bound)
        state['ack']=True;flow.startup_waiting=False;s=o.next_snapshot(bound)
        original=o.host_view
        def expired(snapshot):
            result=original(snapshot);flow._startup_ceiling=time.monotonic_ns()-1;return result
        flow.native.host_view=expired
        with self.assertRaises(F.C.Rejected) as e:flow.observe_commands_instruction(s)
        self.assertEqual(str(e.exception),'deadline');self.assertFalse(flow.commands_instruction_observed)
        c.click.assert_not_called();c.type_ascii.assert_not_called()
    def test_missing_then_partial_view_requires_real_bounded_wheels_before_source(self):
        flow,state,c,o,stop=self.harness(ack_after=0,crop='none')
        bound=flow.startup_wait_ceiling();frontier=flow.host_occurrences.frontier
        def wheel(*args):
            self.assertFalse(state['configured']);self.assertFalse(flow.commands_instruction_observed)
            self.assertEqual(flow.startup_wait_ceiling(),bound)
            state['crop']='partial' if state['crop']=='none' else 'full'
        c.scroll_down.side_effect=wheel;c.scroll_up.side_effect=wheel
        with self.assertRaises(stop):flow.run()
        self.assertEqual(state['captures'],2);self.assertEqual(flow.host_visibility_steps,2)
        c.scroll_down.assert_called_once();c.scroll_up.assert_called_once();c.click.assert_called_once()
        self.assertEqual(flow.host_occurrences.frontier,frontier);self.assertEqual(flow.host_stage,'Operational')
        c.type_ascii.assert_not_called();c._command.assert_not_called();c.observe.assert_not_called()
    def test_permanently_missing_view_keeps_original_visibility_budget(self):
        flow,state,c,o,_=self.harness(ack_after=0,crop='none')
        bound=flow.startup_wait_ceiling()
        with self.assertRaises(F.C.Rejected) as e:flow.run()
        self.assertEqual(str(e.exception),'input_budget');self.assertEqual(flow.host_visibility_steps,128)
        self.assertEqual(flow.startup_wait_ceiling(),bound);self.assertFalse(flow.commands_instruction_observed)
        self.assertEqual(state['captures'],0);c.click.assert_not_called();c._command.assert_not_called()

class PreparedHostContextTests(unittest.TestCase):
    def harness(self,change=None,initial_complete=False):
        from unittest import mock
        class Begun(Exception):pass
        prompt='Type APPROVE 0123456789abcdef to approve this exact operation, or anything else to reject: '
        old='Original primary financial passphrase: '
        state=dict(generation=0,begun=False,views=0)
        class Observer:
            expected_profile=F.C.SEMANTIC_PROFILE
            def read(self):return []
            def next_snapshot(self,deadline):
                if state['begun']:raise Begun()
                state['generation']+=1
                fresh=initial_complete or state['generation']>1;text=old+(prompt if fresh else 'Type APPROVE ')
                result=dict(phase='Selecting',subphase='None',owner=None,view_generation=state['generation'],
                    focused=True,secret_input=False,host_input=False,pixels_per_point=1,viewport=[1280,800],
                    host_view_id=5 if fresh else 4,host_observation=dict(revision=5 if fresh else 4,
                        nonws_end=F.H.count(text),context_valid=True,entry='Idle',editor=None,
                        view=dict(rect=[10,10,600,230],nonws=F.H.count(text),rows=4)),widgets=[
                        dict(tag='HostOutput',owner=None,enabled=True,rect=[0,0,640,240]),
                        dict(tag='BeginHostLine',owner=None,enabled=True,rect=[10,250,200,280])])
                if state['generation']>=8 and change is not None:
                    if change=='context':result['host_observation']['revision']=6;result['host_view_id']=6
                    elif change=='phase':result.update(phase='Waiting',owner='Signer1')
                    else:
                        result['host_view_id']=None;result['host_observation']['view']=None
                        if change=='focus':result['focused']=False
                        elif change=='host':result['host_input']=True
                        elif change=='secret':result['secret_input']=True
                return result
            def host_view(self,s):
                state['views']+=1;h=s['host_observation'];text=old+prompt
                F.C.match_host_view(s,dict(id=5,view_generation=s['view_generation'],revision=5,
                    nonws_end=F.H.count(text),view=h['view'],text=text))
                return text
        fixture=mock.Mock(deadline_ns=time.monotonic_ns()+F.C.ORIGINAL_NS)
        controller=mock.Mock()
        def click(x,y):
            self.assertEqual((x,y),(105,265));self.assertFalse(state['begun']);state['begun']=True
        controller.click.side_effect=click
        flow=F.FullFlow(controller,fixture,Observer(),None)
        flow.startup_index=4;flow.host_lines=4;flow.startup_focus_seen=True
        flow.host_occurrences.frontier=F.H.count(old)
        return flow,state,controller,Begun
    def test_real_capture_advancing_before_bracket_reobserves_before_single_begin(self):
        flow,state,controller,Begun=self.harness()
        bound=flow.startup_wait_ceiling()
        with self.assertRaises(Begun):flow.run()
        self.assertEqual(state['views'],1);controller.click.assert_called_once()
        self.assertEqual(flow.host_lines,5);self.assertEqual(flow.startup_issued,4)
        self.assertEqual(flow.pending_host,('public','APPROVE 0123456789abcdef'))
        self.assertEqual(flow.pending_occurrence[2],5);self.assertEqual(flow.startup_wait_ceiling(),bound)
        controller.type_ascii.assert_not_called();controller._command.assert_not_called();controller.observe.assert_not_called()
    def test_second_context_phase_or_protection_change_still_rejects_without_begin(self):
        for change in ('context','phase','focus','host','secret'):
            with self.subTest(change=change):
                flow,state,c,_=self.harness(change=change);bound=flow.startup_wait_ceiling()
                with self.assertRaises(F.C.Rejected) as e:flow.run()
                self.assertEqual(str(e.exception),'input_phase')
                self.assertEqual(flow.startup_issued,4);self.assertEqual(flow.host_lines,4)
                self.assertEqual(len(flow.challenges),1);self.assertIsNone(flow.pending_host)
                self.assertEqual(flow.startup_wait_ceiling(),bound)
                c.click.assert_not_called();c.type_ascii.assert_not_called();c._command.assert_not_called()
    def test_same_context_retains_immediate_begin_and_expiry_never_renews(self):
        from unittest import mock
        flow,state,c,_=self.harness(initial_complete=True)
        s=flow.snapshot();self.assertTrue(flow.pump_host(s));self.assertTrue(state['begun'])
        c.click.assert_called_once();self.assertEqual(flow.host_lines,5)
        flow,state,c,_=self.harness();bound=flow.startup_wait_ceiling()
        s=flow.snapshot();self.assertTrue(flow.pump_host(s));self.assertFalse(state['begun'])
        self.assertEqual(flow.startup_wait_ceiling(),bound)
        with mock.patch.object(F.time,'monotonic_ns',return_value=bound):
            with self.assertRaises(F.C.Rejected) as e:flow.run()
        self.assertEqual(str(e.exception),'deadline');self.assertEqual(flow.startup_wait_ceiling(),bound)
        c.click.assert_not_called();c.type_ascii.assert_not_called();c._command.assert_not_called()

class LastValidatedObservationTests(unittest.TestCase):
    setUp=SemanticHostObserverTests.setUp
    tearDown=SemanticHostObserverTests.tearDown
    record=SemanticHostObserverTests.record
    records=SemanticHostObserverTests.records
    write=SemanticHostObserverTests.write
    def test_contiguous_phase_timing_and_mutation_isolation(self):
        rows=self.records()
        for i,r in enumerate(rows):r['elapsed_ns']=i+1
        for phase,owner in [('V3Preparing','Signer1'),('V3Preparing','Signer1'),('Selecting',None)]:
            s=self.copy(self.snapshot);s.update(phase=phase,owner=owner,view_generation=len(rows))
            rows.append(self.record('UiSnapshot',s,len(rows)+1));rows[-1]['elapsed_ns']=len(rows)
        self.write(rows);returned=self.o.read();d=self.o.failure_diagnostics()
        self.assertEqual(d['timing']['last_phase'],dict(phase='Selecting',subphase='None',owner=None,first_elapsed_ns=6,last_elapsed_ns=6,snapshot_count=1))
        self.assertEqual(d['timing']['coordinator_last_elapsed_ns'],6)
        self.assertGreater(d['timing']['observer_remaining_ns'],0)
        returned[-1]['facts']['phase']='Finished';d['timing']['last_phase']['phase']='Finished'
        self.assertEqual(self.o.failure_diagnostics()['timing']['last_phase']['phase'],'Selecting')
    def test_later_boundary_without_new_snapshot_commits_then_fails_immediately(self):
        from unittest import mock
        import io,contextlib
        rows=self.records();self.write(rows);self.o.next_snapshot(self.o.deadline_ns)
        stale=list(rows)
        rows.append(self.record('NativeFailureBoundary',NativeFailureBoundaryTests().facts(),4));self.write(rows)
        now=time.monotonic_ns();bound=now+1000
        with mock.patch.object(O.time,'monotonic_ns',side_effect=[now,now,now]):
            with mock.patch.object(O.time,'sleep') as sleep:
                with self.assertRaises(O.C.Rejected) as e:self.o.next_snapshot(bound)
        self.assertEqual(str(e.exception),'observer_failure');sleep.assert_not_called()
        flow=mock.Mock(observer=self.o,records=stale,expected_profile=O.C.SEMANTIC_PROFILE)
        container=F.load('ci-financial-container');output=io.StringIO()
        with mock.patch.object(self.o,'read',side_effect=AssertionError('late IO')):
            with mock.patch.object(O.time,'monotonic_ns',side_effect=AssertionError('late clock')):
                with contextlib.redirect_stdout(output):
                    container.emit_cached_native_failure(flow);container.emit_cached_progress_failure(flow);container.emit_cached_observation_timing_failure(flow)
        self.assertIn('"availability":"Observed"',output.getvalue());self.assertIn('"ui":"FocusLost"',output.getvalue())
        self.assertEqual(len(flow.records),3)
    def test_invalid_append_preserves_prior_complete_summary(self):
        rows=self.records();self.write(rows);self.o.read();before=self.o.failure_diagnostics()
        p=self.directory/'100.jsonl';p.write_bytes(p.read_bytes()+b'{"unknown":true}\n')
        with self.assertRaises(O.C.Rejected):self.o.read()
        self.assertEqual(self.o.failure_diagnostics(),before)
    def test_torn_append_is_not_diagnostic_evidence(self):
        rows=self.records();self.write(rows);self.o.read();before=self.o.failure_diagnostics()
        p=self.directory/'100.jsonl';p.write_bytes(p.read_bytes()+b'{"kind":"NativeFailureBoundary"')
        self.o.read();after=self.o.failure_diagnostics()
        self.assertEqual(after['progress'],before['progress']);self.assertEqual(after['native'],before['native'])
        with self.assertRaises(O.C.Rejected):self.o.read(final=True)
        self.assertEqual(self.o.failure_diagnostics(),after)
    def test_late_validation_cannot_commit_original_or_subordinate_bound(self):
        from unittest import mock
        rows=self.records();self.write(rows);self.o.read();before=self.o.failure_diagnostics()
        for bound in (self.o.deadline_ns,self.o.deadline_ns-1_000_000):
            with mock.patch.object(O.time,'monotonic_ns',side_effect=[bound-1,bound]):
                with self.assertRaises(O.C.Rejected) as e:self.o.read(deadline_ns=bound)
            self.assertEqual(str(e.exception),'deadline');self.assertEqual(self.o.failure_diagnostics(),before)
    def test_unobserved_and_no_coordinator_and_decreasing_elapsed(self):
        d=self.o.failure_diagnostics();self.assertEqual(d['timing']['availability'],'Unavailable')
        self.o.read();d=self.o.failure_diagnostics();self.assertEqual(d['timing']['availability'],'Observed');self.assertIsNone(d['timing']['coordinator_last_elapsed_ns'])
        rows=self.records();rows[0]['elapsed_ns']=20;rows[1]['elapsed_ns']=10;self.write(rows)
        self.o.read();d=self.o.failure_diagnostics();self.assertEqual(d['timing']['availability'],'Unavailable')
        self.assertEqual(d['progress']['phase_counts'][O.C.DIAGNOSTIC_PHASES.index('Selecting')],1)
    def test_strict_timing_schema(self):
        self.write(self.records());self.o.read();v=self.o.failure_diagnostics()['timing'];O.C.validate_observation_timing_diagnostic(v)
        mutations=[dict(v,version=True),dict(v,extra=0),dict(v,observer_remaining_ns=0),dict(v,coordinator_last_elapsed_ns=True),dict(v,availability='Unavailable')]
        for key,value in [('phase','unknown'),('owner','Host'),('snapshot_count',True),('first_elapsed_ns',1),('last_elapsed_ns',-1)]:
            bad=self.copy(v);bad['last_phase'][key]=value;mutations.append(bad)
        for bad in mutations:
            with self.subTest(bad=bad):
                with self.assertRaises(O.C.Rejected):O.C.validate_observation_timing_diagnostic(bad)
    def test_cached_progress_matches_existing_strict_projection(self):
        rows=self.records();self.write(rows);self.o.read()
        self.assertEqual(self.o.failure_diagnostics()['progress'],O.C.cached_progress_diagnostic(rows,O.C.SEMANTIC_PROFILE))
