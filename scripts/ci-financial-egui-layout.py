#!/usr/bin/env python3
"""D-only source-bound egui review diagnostic; never a live qualification.

The H61 FullFlow/NativeScenario and Controller input methods are imported byte
for byte. Only the subprocess transport, frame clock, fixture and observer are
test doubles. Every event is delivered to an actual egui frame. A frame-progress
call is ONE 16 ms frame, not animation settlement and not a Weston receipt.
No DTO text is read here; no Final, Host operation or native authority is used.
"""
import argparse
import hashlib
import importlib.util
import json
import math
import os
import pathlib
import selectors
import signal
import stat
import subprocess
import sys
import time

ROOT = pathlib.Path(__file__).resolve().parent
TEST = 'financial_source_ui::egui_layout_tests::actual_admit_review_layout_protocol'
PREFIX = b'EGUI_LAYOUT_FRAME_V1 '
DTO_ENV = 'WHOLEPACT_CI_EGUI_ADMIT_FIXTURE'
MAX_FRAMES = 4096
FRAME_MS = 16
OBSERVATION_MIN_MS = 100
THROTTLE_ANCHOR = '''if f.last_protected == Some(protected)
            && f.last_emit_at.is_some_and(|t| t.elapsed() < std::time::Duration::from_millis(100)) {
            f.widgets.clear(); return Ok(());
        }'''
DIAGNOSTIC_CODES = frozenset('''controller_source_pin observation_cadence_source_pin
protocol_shape protocol_sequence protocol_clock protocol_phase protocol_host_view
protocol_host_context protocol_widget protocol_geometry protocol_state protocol_gate
wall_deadline child_exit child_pipe child_output_bound child_protocol_eof frame_bound
child_initialization input_button input_forbidden progress_bound host_observation_forbidden
dto_missing dto_path dto_metadata report_bound initial_gate_control arm_attempt_missing
process_or_io child_cleanup test_binary'''.split())
PINS = {
    'ci-financial-flow.py': '53897379193db82848366970474a095c11ce7553373e9a10e400b84dca2a0a67',
    'ci-financial-scenario.py': 'db76d745c672a002cafe22b6195acd6ab5c2073a89fe79e4aad75d1cda6fc98e',
    'ci-financial-controller.py': '9e715b8aed8483eb24221b08ea5c45848740dfa90acc6e7cbfae520758d9a1ba',
    'ci-financial-contract.py': 'e50e10802466562816da6249e91914de739d77d315c001a8e958489e3ddeed41',
    'ci-financial-host-context.py': 'b36927b5ffa178ddebeb68c2570902975a28565b759f02db2a3911cb74eccf11',
    'ci-financial-fixture.py': 'cc71e8bcfb10d009495a2957f547b576dbf7e6a4f8f11f3f3f611010f7b249f6',
}


class DiagnosticError(Exception):
    """Closed, content-free diagnostic failure; never contains child output."""


def require(ok, code):
    if not ok:
        raise DiagnosticError(code)


def load_flow():
    for name, digest in PINS.items():
        require(hashlib.sha256((ROOT / name).read_bytes()).hexdigest() == digest,
                'controller_source_pin')
    observation_source = (ROOT.parent / 'crates/wholepact-financial-coordinator/src/financial_ci.rs').read_text()
    require(observation_source.count(THROTTLE_ANCHOR) == 1, 'observation_cadence_source_pin')
    spec = importlib.util.spec_from_file_location('egui_layout_full_flow', ROOT / 'ci-financial-flow.py')
    flow = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = flow
    spec.loader.exec_module(flow)
    return flow


def exact(value, keys):
    require(type(value) is dict and set(value) == set(keys), 'protocol_shape')


def finite(value, low=-10_000_000, high=10_000_000):
    return type(value) in (int, float) and math.isfinite(value) and low <= value <= high


def validate_frame(row, sequence, contract):
    exact(row, ('seq', 'snapshot', 'geometry', 'state', 'elapsed_ms'))
    require(type(row['seq']) is int and row['seq'] == sequence, 'protocol_sequence')
    require(type(row['elapsed_ms']) is int and row['elapsed_ms'] == sequence * FRAME_MS,
            'protocol_clock')
    snapshot = contract.validate_snapshot(row['snapshot'], contract.SEMANTIC_PROFILE)
    require(snapshot['phase'] == 'V3AdmitReview' and snapshot['subphase'] == 'None'
            and snapshot['owner'] == 'Signer1' and snapshot['focused']
            and not snapshot['secret_input'] and not snapshot['host_input'], 'protocol_phase')
    require(snapshot['host_view_id'] is None, 'protocol_host_view')
    require(snapshot['host_observation'] == dict(revision=0, nonws_end=0,
            context_valid=True, entry='Idle', editor=None, view=None), 'protocol_host_context')
    require(all(w['tag'] in ('ReviewBody', 'ReviewAcknowledgement', 'ArmV3Admit',
            'ScrollRegion', 'BeginHostLine', 'HostOutput') for w in snapshot['widgets']),
            'protocol_widget')
    geometry = row['geometry']
    exact(geometry, ('content_height', 'viewport_height', 'offset_y', 'outer_offset_y',
          'outer_content_height', 'outer_viewport_height', 'inner_rect', 'outer_rect',
          'end_label_rect', 'end_label_visible'))
    require(all(finite(geometry[k], 0) for k in ('content_height', 'viewport_height',
            'offset_y', 'outer_offset_y', 'outer_content_height', 'outer_viewport_height')),
            'protocol_geometry')
    for key in ('inner_rect', 'outer_rect', 'end_label_rect'):
        rect = geometry[key]
        require(type(rect) is list and len(rect) == 4 and all(finite(v) for v in rect)
                and rect[0] <= rect[2] and rect[1] <= rect[3], 'protocol_geometry')
    require(type(geometry['end_label_visible']) is bool, 'protocol_geometry')
    exact(row['state'], ('read_to_end', 'acknowledged', 'arm_enabled', 'arm_clicked'))
    require(all(type(v) is bool for v in row['state'].values()), 'protocol_state')
    require(not row['state']['arm_enabled'] or
            (row['state']['read_to_end'] and row['state']['acknowledged']), 'protocol_gate')
    require(not row['state']['arm_clicked'] or row['state']['arm_enabled'], 'protocol_gate')
    return row


class PipeFrames:
    """Bounded binary test process; stderr and non-protocol stdout are discarded."""
    def __init__(self, binary, contract, deadline_ns):
        self.contract = contract
        self.deadline_ns = deadline_ns
        self.process = None
        self.selector = None
        self.closed = False
        self.cleanup_ok = True
        self.buffer = bytearray()
        self.discarded_bytes = 0
        self.frames = []
        self.last = None
        self.stopped = False
        try:
            self.process = subprocess.Popen([str(binary), '--exact', TEST, '--ignored', '--nocapture',
                '--test-threads=1'], stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                stderr=subprocess.PIPE, start_new_session=True, bufsize=0)
            self.selector = selectors.DefaultSelector()
            self.selector.register(self.process.stdout, selectors.EVENT_READ, 'stdout')
            self.selector.register(self.process.stderr, selectors.EVENT_READ, 'stderr')
        except BaseException as error:
            self.close()
            if not isinstance(error, Exception):
                raise
            raise DiagnosticError('child_initialization') from None

    def remaining(self):
        value = (self.deadline_ns - time.monotonic_ns()) / 1e9
        require(value > 0, 'wall_deadline')
        return value

    def send(self, value):
        self.remaining()
        require(self.process.poll() is None, 'child_exit')
        try:
            self.process.stdin.write(json.dumps(value, separators=(',', ':')).encode() + b'\n')
            self.process.stdin.flush()
        except (OSError, ValueError):
            raise DiagnosticError('child_pipe') from None

    def read_row(self):
        while True:
            if b'\n' in self.buffer:
                line, _, remainder = self.buffer.partition(b'\n')
                self.buffer = bytearray(remainder)
                if PREFIX in line:
                    raw = bytes(line.split(PREFIX, 1)[1])
                    # libtest may put its fixed test-name prefix on this line.
                    return self.contract.loads(raw, limit=65536)
                self.discarded_bytes += len(line) + 1
                require(self.discarded_bytes <= 1_048_576, 'child_output_bound')
                continue
            require(len(self.buffer) <= 65536, 'child_output_bound')
            ready = self.selector.select(self.remaining())
            require(bool(ready), 'wall_deadline')
            for key, _ in ready:
                chunk = os.read(key.fileobj.fileno(), 65536)
                if not chunk:
                    self.selector.unregister(key.fileobj)
                    if key.data == 'stdout':
                        raise DiagnosticError('child_protocol_eof')
                elif key.data == 'stdout':
                    self.buffer.extend(chunk)
                else:
                    self.discarded_bytes += len(chunk)
                    require(self.discarded_bytes <= 1_048_576, 'child_output_bound')

    def frame(self, event=None, *, reason='snapshot'):
        require(len(self.frames) < MAX_FRAMES, 'frame_bound')
        self.send(dict(kind='Frame', dt_ms=FRAME_MS, event=event))
        row = validate_frame(self.read_row(), len(self.frames) + 1, self.contract)
        self.last = row
        # No raw native text, report display, DTO, material IDs or runtime data.
        self.frames.append(dict(row, input_event=event, reason=reason))
        return row['snapshot']

    def finish(self):
        self.send(dict(kind='Stop'))
        self.stopped = True
        self.process.stdin.close()
        # Drain bounded, suppressed child output, including any panic, before exit.
        self.discarded_bytes += len(self.buffer)
        self.buffer.clear()
        while self.selector.get_map():
            ready = self.selector.select(self.remaining())
            require(bool(ready), 'wall_deadline')
            for key, _ in ready:
                chunk = os.read(key.fileobj.fileno(), 65536)
                if not chunk:
                    self.selector.unregister(key.fileobj)
                else:
                    self.discarded_bytes += len(chunk)
                    require(self.discarded_bytes <= 1_048_576, 'child_output_bound')
        require(self.process.wait(timeout=self.remaining()) == 0, 'child_exit')

    def close(self):
        if self.closed:
            return self.cleanup_ok
        self.closed = True
        if self.process is not None:
            # Even a reaped leader can leave descendants in its owned session.
            # Attempt every cleanup boundary; never replace the primary failure.
            for sig in (signal.SIGTERM, signal.SIGKILL):
                try:
                    os.killpg(self.process.pid, sig)
                except ProcessLookupError:
                    pass
                except OSError:
                    self.cleanup_ok = False
                try:
                    self.process.wait(timeout=2)
                except subprocess.TimeoutExpired:
                    if sig == signal.SIGKILL:
                        self.cleanup_ok = False
                except OSError:
                    self.cleanup_ok = False
        if self.selector is not None:
            try:
                self.selector.close()
            except (OSError, ValueError):
                self.cleanup_ok = False
        if self.process is not None:
            for stream in (self.process.stdin, self.process.stdout, self.process.stderr):
                try:
                    if stream is not None and not stream.closed:
                        stream.close()
                except (OSError, ValueError):
                    self.cleanup_ok = False
        return self.cleanup_ok


def controller_type(flow):
    class LayoutController(flow.S.K.Controller):
        """Original click/wheel/budget methods; only transport/receipts are stubs."""
        def __init__(self, pipe):
            self.pipe = pipe
            self._sequence = 0
            self._progress = 0
            self._rendered_clicks = False
            self._wait_ceiling_source = None

        def _reject(self, code, origin='local_guard'):
            raise DiagnosticError('controller_' + code)

        def _remaining(self):
            self.pipe.remaining()
            if self._wait_ceiling_source is not None:
                bound = self._wait_ceiling_source()
                require(bound is None or time.monotonic_ns() < bound, 'wall_deadline')

        def _command(self, op, a=0, b=0):
            self._remaining()
            self._budget(1)
            k = flow.S.K
            if op == k.MOVE:
                event = dict(kind='Move', x=a, y=b)
            elif op == k.BUTTON:
                require(a in (0, 1) and b == 0, 'input_button')
                event = dict(kind='Button', pressed=bool(a))
            elif op in (k.SCROLL_DOWN, k.SCROLL_UP):
                # Weston +120 down -> egui Point delta_y -120 (content up).
                event = dict(kind='Wheel', delta_y=-120 if op == k.SCROLL_DOWN else 120)
            else:
                raise DiagnosticError('input_forbidden')
            self._sequence += 1
            self.pipe.frame(event, reason='input')

        def wait_render_progress(self):
            self._remaining()
            self._budget(1)
            require(self._progress < flow.S.K.MAX_PROGRESS, 'progress_bound')
            self._progress += 1
            self._sequence += 1
            self.pipe.frame(reason='progress_stub')

    return LayoutController


class LayoutFixture:
    """No actual fixture authority; same non-renewed 120 s wall bound for this test."""
    def __init__(self, contract):
        self.contract = contract
        self.started_ns = time.monotonic_ns()
        self.deadline_ns = self.started_ns + contract.ACTION_NS

    def check(self):
        self.contract.require(time.monotonic_ns() < self.deadline_ns, 'deadline')

    def preflight_input_budget(self):
        return 0


class LayoutObserver:
    """Actual geometry frames; no proof records, Host text, or authority claims."""
    def __init__(self, pipe, contract):
        self.pipe = pipe
        self.expected_profile = contract.SEMANTIC_PROFILE
        self.last_observation_ms = None

    def next_snapshot(self, deadline):
        require(time.monotonic_ns() < deadline, 'wall_deadline')
        # Source finish_impl has a 100 ms minimum snapshot-emission interval.
        # Fixed empty 16 ms frames model that minimum, never wait for a chosen
        # geometry/state or retry a rejected stable check. Not a wall-time claim.
        if self.last_observation_ms is not None:
            while ((len(self.pipe.frames) + 1) * FRAME_MS
                   - self.last_observation_ms < OBSERVATION_MIN_MS):
                self.pipe.frame(reason='observation_gap_stub')
        result = self.pipe.frame()
        self.last_observation_ms = len(self.pipe.frames) * FRAME_MS
        return result

    def host_view(self, *args, **kwargs):
        raise DiagnosticError('host_observation_forbidden')

    def read(self):
        return []


def counters(driver):
    def count(*key):
        return driver.scrolls.get(('V3AdmitReview', 'None', *key), 0)
    return dict(actions=driver.actions, seek_body=count('seek', 'ReviewBody', 'Signer1'),
        seek_ack=count('seek', 'ReviewAcknowledgement', 'Signer1'),
        seek_arm=count('seek', 'ArmV3Admit', 'Signer1'),
        outer_up=count('ScrollRegion', None, 'up'), outer_down=count('ScrollRegion', None, 'down'),
        body_down=count('ReviewBody', 'Signer1', 'down'),
        owed_body_wheel=bool(count('review-scroll-pending', 'ArmV3Admit', 'Signer1', 'ReviewBody')))


def private_dto_metadata():
    value = os.environ.get(DTO_ENV)
    require(value is not None, 'dto_missing')
    path = pathlib.Path(value)
    require(path.is_absolute(), 'dto_path')
    info = path.lstat()
    require(stat.S_ISREG(info.st_mode) and stat.S_IMODE(info.st_mode) == 0o600
            and info.st_uid == os.getuid() and 0 < info.st_size <= 61440, 'dto_metadata')
    return path, (info.st_dev, info.st_ino)


def write_private(path, report):
    encoded = (json.dumps(report, separators=(',', ':'), allow_nan=False) + '\n').encode()
    require(len(encoded) <= 16_777_216, 'report_bound')
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, 'wb') as target:
        target.write(encoded)


def public_summary(report, flow):
    """Closed finite projection only; full frame trace stays in the private file."""
    frames = report['frames']
    require(type(frames) is list and len(frames) <= MAX_FRAMES, 'report_bound')
    require(report['outcome'] in ('source_bound_arm_reachable', 'controller_rejected',
            'diagnostic_rejected'), 'report_bound')
    code = report.get('failure_code')
    allowed = DIAGNOSTIC_CODES | flow.C.ERRORS | frozenset('controller_' + v for v in flow.S.K.ERRORS)
    require(code is None or code in allowed, 'report_bound')
    count = report['counters']
    if count is not None:
        exact(count, ('actions', 'seek_body', 'seek_ack', 'seek_arm', 'outer_up',
              'outer_down', 'body_down', 'owed_body_wheel'))
        require(type(count['owed_body_wheel']) is bool and all(type(v) is int and 0 <= v <= 513
                for k, v in count.items() if k != 'owed_body_wheel'), 'report_bound')
    final = frames[-1] if frames else None
    if final is not None:
        native = {k: v for k, v in final.items() if k not in ('input_event', 'reason')}
        validate_frame(native, len(frames), flow.C)
    elapsed = report['wall_elapsed_ns']
    require(type(elapsed) is int and 0 <= elapsed <= 180_000_000_000, 'report_bound')
    result = dict(schema=1, classification='D-source-bound-egui-diagnostic-only',
        outcome=report['outcome'], failure_code=code, frames=len(frames),
        input_events_delivered=sum(r['input_event'] is not None for r in frames),
        frame_ms=FRAME_MS, observation_min_ms=OBSERVATION_MIN_MS,
        wall_elapsed_ns=elapsed, simulated_elapsed_ms=0 if final is None else final['elapsed_ms'],
        initial_scroll='fresh-top-not-live-retained-offset',
        final_state=None if final is None else final['state'],
        final_geometry=None if final is None else final['geometry'],
        final_widgets=[] if final is None else [w for w in final['snapshot']['widgets']
            if w['tag'] in ('ReviewBody', 'ReviewAcknowledgement', 'ArmV3Admit')],
        counters=count, first_transition_seq={key: next((r['seq'] for r in frames if r['state'][key]), None)
            for key in ('read_to_end', 'acknowledged', 'arm_enabled', 'arm_clicked')},
        cleanup_ok=report.get('cleanup_ok'))
    require(result['cleanup_ok'] is None or type(result['cleanup_ok']) is bool, 'report_bound')
    require(len(json.dumps(result, allow_nan=False).encode()) <= 16384, 'report_bound')
    return validate_summary(result)


def validate_summary(value):
    """Import-safe strict validator for the outer hosted driver's stdout sink."""
    require(type(value) is dict, 'report_bound')
    if value.get('outcome') == 'diagnostic_setup_rejected':
        exact(value, ('schema', 'outcome'))
        require(type(value['schema']) is int and value['schema'] == 1, 'report_bound')
        return value
    exact(value, ('schema', 'classification', 'outcome', 'failure_code', 'frames',
          'input_events_delivered', 'frame_ms', 'observation_min_ms', 'wall_elapsed_ns',
          'simulated_elapsed_ms', 'initial_scroll', 'final_state', 'final_geometry',
          'final_widgets', 'counters', 'first_transition_seq', 'cleanup_ok'))
    require(type(value['schema']) is int and value['schema'] == 1 and
            value['classification'] == 'D-source-bound-egui-diagnostic-only', 'report_bound')
    require(value['outcome'] in ('source_bound_arm_reachable', 'controller_rejected',
            'diagnostic_rejected'), 'report_bound')
    flow = load_flow()
    allowed = DIAGNOSTIC_CODES | flow.C.ERRORS | frozenset('controller_' + v for v in flow.S.K.ERRORS)
    code = value['failure_code']
    require(code is None or (type(code) is str and code in allowed), 'report_bound')
    count = value['frames']
    require(type(count) is int and 0 <= count <= MAX_FRAMES, 'report_bound')
    require(type(value['input_events_delivered']) is int and
            0 <= value['input_events_delivered'] <= count, 'report_bound')
    require(type(value['frame_ms']) is int and value['frame_ms'] == FRAME_MS and
            type(value['observation_min_ms']) is int and value['observation_min_ms'] == OBSERVATION_MIN_MS,
            'report_bound')
    require(type(value['simulated_elapsed_ms']) is int and
            value['simulated_elapsed_ms'] == count * FRAME_MS, 'report_bound')
    require(type(value['wall_elapsed_ns']) is int and
            0 <= value['wall_elapsed_ns'] <= 180_000_000_000, 'report_bound')
    require(value['initial_scroll'] == 'fresh-top-not-live-retained-offset', 'report_bound')
    require(value['cleanup_ok'] is None or type(value['cleanup_ok']) is bool, 'report_bound')
    counters_value = value['counters']
    if counters_value is not None:
        exact(counters_value, ('actions', 'seek_body', 'seek_ack', 'seek_arm', 'outer_up',
              'outer_down', 'body_down', 'owed_body_wheel'))
        require(type(counters_value['owed_body_wheel']) is bool and all(type(v) is int and 0 <= v <= 513
                for k, v in counters_value.items() if k != 'owed_body_wheel'), 'report_bound')
    states = ('read_to_end', 'acknowledged', 'arm_enabled', 'arm_clicked')
    exact(value['first_transition_seq'], states)
    require(all(v is None or (type(v) is int and 1 <= v <= count)
            for v in value['first_transition_seq'].values()), 'report_bound')
    widgets = value['final_widgets']
    require(type(widgets) is list and len(widgets) <= 3, 'report_bound')
    if count == 0:
        require(value['final_state'] is None and value['final_geometry'] is None and not widgets,
                'report_bound')
    else:
        require(all(type(w) is dict and w.get('tag') in ('ReviewBody', 'ReviewAcknowledgement', 'ArmV3Admit')
                    and w.get('owner') == 'Signer1' for w in widgets), 'report_bound')
        # Reuse exact frame geometry/state and original snapshot rectangle checks.
        snapshot = dict(phase='V3AdmitReview', subphase='None', owner='Signer1', view_generation=1,
            focused=True, secret_input=False, host_input=False, pixels_per_point=1, viewport=[1280, 800],
            widgets=widgets, host_view_id=None, host_observation=dict(revision=0, nonws_end=0,
                context_valid=True, entry='Idle', editor=None, view=None))
        validate_frame(dict(seq=count, elapsed_ms=value['simulated_elapsed_ms'], snapshot=snapshot,
            geometry=value['final_geometry'], state=value['final_state']), count, flow.C)
    if value['outcome'] == 'source_bound_arm_reachable':
        require(code is None and count > 0 and value['final_state']['arm_clicked'] and
                value['cleanup_ok'] is True, 'report_bound')
    else:
        require(code is not None, 'report_bound')
    require(len(json.dumps(value, allow_nan=False).encode()) <= 16384, 'report_bound')
    return value


def run(binary):
    flow = load_flow()
    contract = flow.C
    fixture = LayoutFixture(contract)
    pipe = None
    driver = None
    report = dict(schema=1, classification='D-source-bound-egui-diagnostic-only',
        h61_commit='2fcb659ad2316c81585e76c9aa4208a9c15f2711', controller_sources=PINS,
        test=TEST, viewport=[1280, 800], frame_ms=FRAME_MS, wall_bound_ns=contract.ACTION_NS,
        wall_bound_origin='diagnostic-start-not-retained-native-window',
        initial_scroll='fresh-top-not-live-retained-offset',
        observation_min_ms=OBSERVATION_MIN_MS,
        observation_throttle_anchor_sha256=hashlib.sha256(THROTTLE_ANCHOR.encode()).hexdigest(),
        transport='test-subprocess-not-Weston', frame_clock='simulated-not-live-cadence',
        authority='none-Arm-dry-intercept-Final-forbidden', outcome='not_started',
        initial_control=None, counters=None, frames=[], review_steps=[])
    try:
        pipe = PipeFrames(binary, contract, fixture.deadline_ns)
        controller = controller_type(flow)(pipe)
        observer = LayoutObserver(pipe, contract)
        driver = flow.FullFlow(controller, fixture, observer, None)
        # Same real composition, two harmless frames; no separate toy fixture.
        driver.snapshot()
        snapshot = driver.snapshot()
        initial = pipe.last['state']
        report['initial_control'] = dict(initial)
        require(not any(initial.values()), 'initial_gate_control')
        while True:
            fixture.check()
            report['review_steps'].append(dict(sequence=pipe.last['seq'],
                view_generation=snapshot['view_generation'], counters=counters(driver)))
            driver.review(snapshot, 'ArmV3Admit', 'Signer1')
            if pipe.last['state']['arm_clicked']:
                require(driver.used(snapshot, 'ArmV3Admit', 'Signer1'), 'arm_attempt_missing')
                report['outcome'] = 'source_bound_arm_reachable'
                break
            snapshot = driver.snapshot()
        pipe.finish()
    except contract.Rejected as error:
        report['outcome'] = 'controller_rejected'
        report['failure_code'] = error.code
    except DiagnosticError as error:
        report['outcome'] = 'diagnostic_rejected'
        report['failure_code'] = str(error)
    except (OSError, ValueError, subprocess.SubprocessError):
        report['outcome'] = 'diagnostic_rejected'
        report['failure_code'] = 'process_or_io'
    finally:
        if driver is not None:
            report['counters'] = counters(driver)
        if pipe is not None:
            report['cleanup_ok'] = pipe.close()
            if not report['cleanup_ok'] and report['outcome'] == 'source_bound_arm_reachable':
                report['outcome'] = 'diagnostic_rejected'
                report['failure_code'] = 'child_cleanup'
            report['frames'] = pipe.frames
            report['state_transitions'] = [dict(sequence=r['seq'], elapsed_ms=r['elapsed_ms'],
                state=r['state']) for i, r in enumerate(pipe.frames)
                if i == 0 or r['state'] != pipe.frames[i - 1]['state']]
            report['input_events_delivered'] = sum(r['input_event'] is not None for r in pipe.frames)
            report['child_returncode'] = pipe.process.returncode
            report['discarded_output_bytes'] = pipe.discarded_bytes
        report['wall_elapsed_ns'] = time.monotonic_ns() - fixture.started_ns
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--coordinator-test-binary', required=True, type=pathlib.Path)
    parser.add_argument('--output', required=True, type=pathlib.Path)
    args = parser.parse_args()
    dto = identity = None
    try:
        dto, identity = private_dto_metadata()
        info = args.coordinator_test_binary.lstat()
        require(args.coordinator_test_binary.is_absolute() and stat.S_ISREG(info.st_mode)
                and os.access(args.coordinator_test_binary, os.X_OK), 'test_binary')
        report = run(args.coordinator_test_binary)
        write_private(args.output, report)
        # Do not print exception objects, paths, raw process output or any DTO.
        print(json.dumps(public_summary(report, load_flow()), separators=(',', ':'), allow_nan=False))
        return 0 if report['outcome'] == 'source_bound_arm_reachable' else 1
    except (DiagnosticError, OSError, ValueError):
        print('{"schema":1,"outcome":"diagnostic_setup_rejected"}')
        return 2
    finally:
        if dto is not None:
            try:
                current = dto.lstat()
                if (current.st_dev, current.st_ino) == identity:
                    dto.unlink()
            except FileNotFoundError:
                pass


if __name__ == '__main__':
    raise SystemExit(main())
