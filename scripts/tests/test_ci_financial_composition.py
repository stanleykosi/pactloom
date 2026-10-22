"""Pure cross-feature checks: no product, compositor, or actual credentials."""
import json
import pathlib
import unittest
from unittest import mock
import test_ci_financial_observer as O
import test_ci_financial_input_batching as B
import test_ci_financial_fixture_diagnostics as D
F=O.F

class ComposedStartupTests(unittest.TestCase):
    def setUp(self):
        self.startup=O.HostStartupContractTests();self.startup.setUp()
        self.addCleanup(self.startup.doCleanups)
    def test_long_owned_writing_does_not_spend_idle_sweep_or_source_actions(self):
        flow=self.startup.flow();flow.startup_index=len(F.HOST_STARTUP);flow.startup_waiting=True
        flow.startup_focus_seen=True;flow.last_phase=('Selecting','None',None)
        key=('Selecting','None','idle_sweep',None);flow.scrolls[key]=63
        base=dict(phase='Selecting',subphase='None',owner=None,focused=True,secret_input=False,widgets=[])
        flow.snapshot=mock.Mock(side_effect=[base|{'host_input':True}]*200+[base|{'host_input':False}])
        flow.idle_scan=mock.Mock(side_effect=AssertionError('no outer scan while startup owns Writing'))
        def source(*args):
            self.assertTrue(flow.host_startup_complete)
            self.assertEqual(flow.scrolls[key],63)
            raise F.C.Rejected('missing_evidence')
        flow.save_selector=mock.Mock(side_effect=source)
        with self.assertRaises(F.C.Rejected) as error:flow.run()
        self.assertEqual(error.exception.code,'missing_evidence')
        self.assertEqual(flow.controller.wait_render_progress.call_count,200)
        flow.save_selector.assert_called_once();flow.idle_scan.assert_not_called()
        flow.controller.click.assert_not_called();flow.controller.scroll_up.assert_not_called()
        flow.controller.scroll_down.assert_not_called();self.assertEqual(flow.scrolls[key],63)
    def test_poststartup_writing_in_selecting_and_waiting_never_scrolls_captures_or_inputs(self):
        for phase,owner in (('Selecting',None),('Waiting','Signer1'),('SetupNeeded','Signer1')):
            with self.subTest(phase=phase):
                flow=self.startup.flow();flow.startup_index=len(F.HOST_STARTUP)
                flow.startup_focus_seen=True
                base=dict(phase=phase,subphase='None',owner=owner,focused=True,secret_input=False,host_input=True,widgets=[])
                flow.snapshot=mock.Mock(side_effect=[base]*100+[base|{'phase':'Revoked','host_input':False}])
                flow.save_selector=mock.Mock(side_effect=AssertionError('source effect while Host Writing'))
                flow.idle_scan=mock.Mock(side_effect=AssertionError('scroll while Host Writing'))
                flow.native.capture_host=mock.Mock(side_effect=AssertionError('capture while Host Writing'))
                with self.assertRaises(F.C.Rejected) as error:flow.run()
                self.assertEqual(error.exception.code,'source_failure')
                self.assertEqual(flow.controller.wait_render_progress.call_count,100)
                flow.save_selector.assert_not_called();flow.idle_scan.assert_not_called()
                flow.native.capture_host.assert_not_called();flow.controller.click.assert_not_called()
                self.assertEqual(flow.actions,0);self.assertEqual(flow.scrolls,{})
    def test_source_password_branch_remains_separate_and_preserved(self):
        flow=self.startup.flow();flow.startup_index=len(F.HOST_STARTUP)
        flow.fixture=mock.Mock();secret=object();flow.fixture.secret.return_value=secret
        snapshot=dict(phase='V3Password',subphase='None',owner='Signer1',focused=True,
                      secret_input=True,host_input=False,widgets=[])
        flow.snapshot=mock.Mock(side_effect=[snapshot,snapshot,snapshot|{'phase':'Revoked'}])
        flow.native.protected_input=mock.Mock();flow.press=mock.Mock()
        with self.assertRaises(F.C.Rejected) as error:flow.run()
        self.assertEqual(error.exception.code,'source_failure')
        flow.fixture.secret.assert_called_once_with('source')
        flow.native.protected_input.assert_called_once_with('V3Password','Signer1','SourcePassword',secret)
        flow.press.assert_called_once_with(snapshot,'PasswordSubmit','Signer1')
        flow.controller.wait_render_progress.assert_not_called()
    def test_complete_reply_stream_and_exact_reviewer_path_use_balanced_bounded_batches(self):
        # Combine both authoritative synthetic fixture shapes without reading a token.
        reviewer=D.ReviewerArtifactTests();reviewer.setUp();self.addCleanup(reviewer.doCleanups)
        fixture=self.startup.fixture;root=self.startup.root
        fixture._data['delivery_choices']=reviewer.choices
        pathlib.Path(fixture._data['delivery_choices_file']).write_text(json.dumps(reviewer.choices))
        for index,source in enumerate(fixture._data['sources'],1):
            account=str(index)*64;entry={'account_id':account};path=root/f'coordinated-fixture-source-{index}-entry.json'
            path.write_text(json.dumps(entry));path.chmod(0o600)
            source.update(entry_selection=entry,entry_selection_file=str(path),reopen_selector={'account_id':account})
            source['original_capture']['scope'].update(account_id=account,participant_id=f'synthetic-participant-{index}')
            source['original_capture']['request']={'operation_id':f'private-original-native-capture-{index}'}
        # Both independently imported fixture modules use the same disposable base.
        with mock.patch.object(F.S.F,'ARTIFACT_PARENT',root.parent):
            flow=self.startup.flow();controller=B.RecordingController();flow.controller=controller
            flow.native.controller=controller
            flow.native.stable=lambda *a,**kw:{'host_input':True,'secret_input':True}
            flow.native.point=lambda *a:(100,100)
            expected=[]
            for index,prompt in enumerate(self.startup.PROMPTS):
                reply=flow.expected_host_line(prompt);self.assertFalse(flow.host_startup_complete)
                kind,value=reply
                if kind=='secret':
                    flow.native.protected_input('Selecting',None,'HostEditor',fixture.secret('host'))
                    expected.extend(B.K._ascii_events(F.S.F._SYNTHETIC_PASSWORDS['host'].decode('ascii')))
                else:
                    controller.type_ascii(value);expected.extend(B.K._ascii_events(value))
                flow.pending_host=reply;flow.pending_startup=index;flow.startup_submitted();flow.pending_host=None
                self.assertFalse(flow.host_startup_complete)
                flow.pump_host({'host_input':True,'secret_input':False})
                self.assertFalse(flow.host_startup_complete)
                flow.pump_host({'host_input':False,'secret_input':False,'widgets':[]})
            self.assertTrue(flow.host_startup_complete)
            kind,path=flow.expected_host_line('Exact coordinated reviewer selection JSON')
            self.assertEqual((kind,path),('public',str(root/'coordinated-reviewer-selection-1.json')))
            self.assertTrue(pathlib.Path(path).is_file());self.assertFalse(path.startswith('{'))
            controller.type_ascii(path);expected.extend(B.K._ascii_events(path))
            self.assertIsNone(flow.expected_host_line('Exact coordinated reviewer selection JSON'))
            self.assertEqual(flow.reviewer_index,1)
            self.assertEqual(tuple(event for batch in controller.batches for event in batch),tuple(expected))
            self.assertTrue(all(B.raw_event_count(batch)+3<=256 for batch in controller.batches))
            self.assertFalse(controller.held);self.assertFalse(controller.pending)
            self.assertFalse((root/'coordinated-host-runtime-session.token').exists())
            self.assertEqual(len(fixture.secret_instances),2)
            self.assertTrue(all(not any(secret._bytes) for secret in fixture.secret_instances))

if __name__=='__main__':unittest.main()
