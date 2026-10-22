"""Pure input regressions; no product, compositor, captures or credential files.

Pinned backend evidence: egui-winit 0.36.2 lib.rs on_keyboard_input emits
Key and Text; key_from_key_code maps ShiftLeft; ModifiersChanged appends an
additional raw event. winit 0.30.13 Wayland keyboard dispatch forwards each
modifier update. A shifted ASCII character therefore permits seven raw events.
"""
import importlib.util
import pathlib
import sys
import unittest

ROOT=pathlib.Path(__file__).resolve().parents[1]
spec=importlib.util.spec_from_file_location('batching_scenario',ROOT/'ci-financial-scenario.py')
S=importlib.util.module_from_spec(spec);spec.loader.exec_module(S)
K=S.K

def raw_event_count(events):
    return sum(2 if key==42 else (2 if down else 1) for key,down in events)

class RecordingController(K.Controller):
    def __init__(self):
        self._sequence=0;self._progress=0;self._receipt=None
        self.commands=[];self.batches=[];self.pending=[];self.held=set()
    def _reject(self,code,*args):raise K.Rejected(code)
    def _command(self,op,a=0,b=0):
        self._sequence+=1;self.commands.append((op,a,b))
        if op==K.KEY:
            if b:self.held.add(a)
            else:self.held.remove(a)
            self.pending.append((a,b))
    def wait_render_progress(self):
        assert not self.held, 'barrier with held key/modifier'
        self._sequence+=1;self._progress+=1
        self.batches.append(tuple(self.pending));self.pending=[]

class InputBatchingTests(unittest.TestCase):
    def protected(self,controller,role='source'):
        native=object.__new__(S.NativeScenario);native.controller=controller
        native.stable=lambda *a,**kw:{'host_input':True,'secret_input':True}
        native.point=lambda *a:(100,100)
        secret=S.F.SyntheticSecret(S.F._TOKEN,S.F._SYNTHETIC_PASSWORDS[role])
        native.protected_input('Selecting',None,'HostEditor',secret)
        self.assertTrue(all(x==0 for x in secret._bytes))
        return secret
    def assert_batches(self,c,text):
        self.assertEqual(tuple(x for batch in c.batches for x in batch),K._ascii_events(text))
        self.assertFalse(c.held);self.assertFalse(c.pending)
        self.assertTrue(all(raw_event_count(batch)<=224 for batch in c.batches))
        # Pointer move/down/up fit the remaining unchanged native256-event bound.
        self.assertTrue(all(raw_event_count(batch)+3<=256 for batch in c.batches))
    def test_before_fix_public64_and_fixed_source_exceed_native_cap(self):
        self.assertEqual(raw_event_count(K._ascii_events('A'*64)),448)
        source=S.F._SYNTHETIC_PASSWORDS['source'].decode('ascii')
        self.assertEqual(raw_event_count(K._ascii_events(source)),295)
        self.assertGreater(295,256)
    def test_shifted_public_batches_are_balanced_and_exact(self):
        c=RecordingController();value='A'*64+'!@#$%^&*()_+{}:"~|<>?'
        c.type_ascii(value);self.assert_batches(c,value)
        self.assertEqual(len(c.batches),3)
    def test_all_printable_ascii_order_unchanged(self):
        c=RecordingController();value=''.join(map(chr,range(32,127)))
        c.type_ascii(value);self.assert_batches(c,value)
    def test_both_actual_synthetic_secrets_are_batched_and_wiped(self):
        for role in ('host','source'):
            with self.subTest(role=role):
                c=RecordingController();self.protected(c,role)
                self.assert_batches(c,S.F._SYNTHETIC_PASSWORDS[role].decode('ascii'))
                self.assertEqual(len(c.batches),2)
    def test_empty_public_input_emits_nothing(self):
        c=RecordingController();c.type_ascii('')
        self.assertEqual(c.commands,[]);self.assertEqual(c.batches,[])
    def test_invalid_suffix_preflight_emits_zero_keys(self):
        for value in ('A'*65+'\n','A'*65+'é','A'*(K.MAX_TEXT+1),None):
            c=RecordingController()
            with self.assertRaises(K.Rejected):c.type_ascii(value)
            self.assertEqual(c.commands,[]);self.assertEqual(c.batches,[])
    def test_public_total_command_and_progress_preflight_emit_zero_keys(self):
        for kind in ('commands','progress'):
            c=RecordingController()
            if kind=='commands':c._sequence=K.MAX_COMMANDS-257 # needs256 keys+2 barriers
            else:c._progress=K.MAX_PROGRESS-1
            with self.assertRaises(K.Rejected):c.type_ascii('A'*64)
            self.assertEqual(c.commands,[]);self.assertEqual(c.batches,[])
    def test_protected_total_budget_preflight_precedes_click_and_keys(self):
        for kind in ('commands','progress'):
            c=RecordingController()
            if kind=='commands':c._sequence=K.MAX_COMMANDS-174 #170 keys+2 barriers+3 click
            else:c._progress=K.MAX_PROGRESS-1
            with self.assertRaises(K.Rejected):self.protected(c)
            self.assertEqual(c.commands,[]);self.assertEqual(c.batches,[])
    def test_key_ack_does_not_require_render_progress(self):
        class Transport:
            def settimeout(self,value):pass
            def send(self,packet,flags):
                cmd=K.COMMAND.unpack(packet)
                self.reply=K.HEADER.pack(K.MAGIC,K.VERSION,cmd[2],K.ACK,0,10,20,0,0,0,0,cmd[2])
                return len(packet)
            def recvmsg(self,*args):return self.reply,[],0,None
            def close(self):pass
        c=K.Controller(Transport(),10**9,10**9,_clock=lambda:1);c._ready=c._bound=True
        for key,down in K._ascii_events('A'*64):c._command(K.KEY,key,down)
        self.assertEqual(c._receipt.frame,20);self.assertEqual(c._sequence,256)
        c.close()

if __name__=='__main__':unittest.main()
