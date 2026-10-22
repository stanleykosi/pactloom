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

if __name__=='__main__':unittest.main()

