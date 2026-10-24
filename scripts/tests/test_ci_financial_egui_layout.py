"""Bridge contract tests only. No egui/runtime/layout qualification is claimed."""
import copy
import importlib.util
import os
import pathlib
import subprocess
import sys
import time
import unittest
from unittest import mock

PATH = pathlib.Path(__file__).resolve().parents[1] / 'ci-financial-egui-layout.py'
SPEC = importlib.util.spec_from_file_location('egui_layout_bridge_tested', PATH)
B = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(B)
F = B.load_flow()


def row():
    return dict(seq=1, elapsed_ms=16, snapshot=dict(phase='V3AdmitReview', subphase='None',
        owner='Signer1', view_generation=1, focused=True, secret_input=False, host_input=False,
        pixels_per_point=1, viewport=[1280, 800], widgets=[], host_view_id=None,
        host_observation=dict(revision=0, nonws_end=0, context_valid=True, entry='Idle',
            editor=None, view=None)), geometry=dict(content_height=1000, viewport_height=390,
        offset_y=0, outer_offset_y=0, outer_content_height=1100, outer_viewport_height=780,
        inner_rect=[0, 0, 1000, 390], outer_rect=[0, 0, 1280, 780],
        end_label_rect=[0, 1000, 100, 1010], end_label_visible=False),
        state=dict(read_to_end=False, acknowledged=False, arm_enabled=False, arm_clicked=False))


class BridgeContractTests(unittest.TestCase):
    def test_exact_source_and_input_methods_are_not_reimplemented(self):
        controller = B.controller_type(F)
        for name in ('click', 'scroll_up', 'scroll_down', '_budget',
                     'enable_rendered_clicks', 'install_wait_ceiling'):
            self.assertIs(getattr(controller, name), getattr(F.S.K.Controller, name))
        self.assertEqual(F.C.ACTION_NS, 120_000_000_000)

    def test_strict_frame_schema_rejects_text_nonfinite_and_authority(self):
        value = row()
        self.assertIs(B.validate_frame(value, 1, F.C), value)
        for alter in (
            lambda r: r.update(display='not permitted'),
            lambda r: r['geometry'].update(offset_y=float('nan')),
            lambda r: r['state'].update(arm_clicked=True),
            lambda r: r.update(seq=2),
            lambda r: r['snapshot'].update(phase='V3AdmitReady'),
            lambda r: r.update(elapsed_ms=17),
        ):
            bad = copy.deepcopy(value)
            alter(bad)
            with self.assertRaises((B.DiagnosticError, F.C.Rejected)):
                B.validate_frame(bad, 1, F.C)
        report = dict(frames=[dict(value, input_event=None, reason='snapshot')],
            outcome='controller_rejected', failure_code='input_widget', counters=None,
            wall_elapsed_ns=1000, cleanup_ok=True)
        summary = B.public_summary(report, F)
        self.assertIs(B.validate_summary(summary), summary)
        self.assertNotIn('frames', summary['final_state'])
        for alter in (
            lambda r: r.update(display='not permitted'),
            lambda r: r.update(failure_code='arbitrary child text'),
            lambda r: r.update(simulated_elapsed_ms=100),
            lambda r: r['final_geometry'].update(offset_y=float('inf')),
        ):
            bad = copy.deepcopy(summary)
            alter(bad)
            with self.assertRaises((B.DiagnosticError, F.C.Rejected)):
                B.validate_summary(bad)
        self.assertEqual(B.validate_summary(dict(schema=1, outcome='diagnostic_setup_rejected')),
                         dict(schema=1, outcome='diagnostic_setup_rejected'))

    def test_original_input_count_and_fixed_axis_mapping(self):
        class Pipe:
            def __init__(self):
                self.calls = []
            def remaining(self):
                return 120
            def frame(self, event=None, *, reason='snapshot'):
                self.calls.append((event, reason))
        pipe = Pipe()
        controller = B.controller_type(F)(pipe)
        F.S.K.Controller.enable_rendered_clicks(controller)
        controller.click(200, 300)
        controller.scroll_down(400, 500)
        controller.wait_render_progress()
        controller.scroll_up(400, 500)
        self.assertEqual(pipe.calls, [
            (dict(kind='Move', x=200, y=300), 'input'),
            (dict(kind='Button', pressed=True), 'input'),
            (dict(kind='Button', pressed=False), 'input'),
            (None, 'progress_stub'),
            (dict(kind='Move', x=400, y=500), 'input'),
            (dict(kind='Wheel', delta_y=-120), 'input'),
            (None, 'progress_stub'),
            (dict(kind='Move', x=400, y=500), 'input'),
            (dict(kind='Wheel', delta_y=120), 'input')])
        self.assertEqual(controller._sequence, 9)
        self.assertEqual(controller._progress, 2)

    def test_constructor_failure_reaps_benign_child(self):
        original = subprocess.Popen
        for fault, expected in ((OSError('test-only'), B.DiagnosticError),
                                (KeyboardInterrupt(), KeyboardInterrupt)):
            with self.subTest(fault=type(fault).__name__):
                children = []
                def benign(_args, **kwargs):
                    child = original([sys.executable, '-c', 'import time; time.sleep(30)'], **kwargs)
                    children.append(child)
                    return child
                with mock.patch.object(B.subprocess, 'Popen', side_effect=benign), \
                     mock.patch.object(B.selectors, 'DefaultSelector', side_effect=fault):
                    with self.assertRaises(expected):
                        B.PipeFrames(pathlib.Path(sys.executable), F.C, time.monotonic_ns() + F.C.ACTION_NS)
                self.assertEqual(len(children), 1)
                self.assertIsNotNone(children[0].returncode)
                self.assertTrue(all(s.closed for s in (children[0].stdin, children[0].stdout, children[0].stderr)))

    def test_observation_gap_is_fixed_not_state_dependent(self):
        class Pipe:
            def __init__(self):
                self.frames = []
            def frame(self, event=None, *, reason='snapshot'):
                self.frames.append(reason)
                return {'opaque': len(self.frames)}
        pipe = Pipe()
        observer = B.LayoutObserver(pipe, F.C)
        deadline = time.monotonic_ns() + F.C.ACTION_NS
        self.assertEqual(observer.next_snapshot(deadline), {'opaque': 1})
        self.assertEqual(observer.next_snapshot(deadline), {'opaque': 8})
        self.assertEqual(pipe.frames, ['snapshot'] + ['observation_gap_stub'] * 6 + ['snapshot'])
        self.assertEqual(observer.last_observation_ms, 128)

    def test_cleanup_kills_descendant_after_leader_exit(self):
        original = subprocess.Popen
        code = ('import subprocess,sys; p=subprocess.Popen([sys.executable,"-c",'
                '"import time; time.sleep(30)"], stdin=subprocess.DEVNULL,'
                'stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL); print(p.pid,flush=True)')
        def benign(_args, **kwargs):
            return original([sys.executable, '-c', code], **kwargs)
        with mock.patch.object(B.subprocess, 'Popen', side_effect=benign):
            pipe = B.PipeFrames(pathlib.Path(sys.executable), F.C, time.monotonic_ns() + F.C.ACTION_NS)
        try:
            pipe.process.wait(timeout=3)
            descendant = int(pipe.process.stdout.readline())
            self.assertTrue(pipe.close())
            end = time.monotonic() + 2
            while time.monotonic() < end:
                path = pathlib.Path('/proc') / str(descendant) / 'stat'
                try:
                    status = path.read_text()
                except (FileNotFoundError, ProcessLookupError):
                    break
                if status.split(') ', 1)[1].startswith('Z '):
                    break
                time.sleep(.01)
            else:
                self.fail('benign descendant survived owned group cleanup')
            self.assertTrue(all(s.closed for s in (pipe.process.stdin, pipe.process.stdout, pipe.process.stderr)))
        finally:
            pipe.close()


if __name__ == '__main__':
    unittest.main()
