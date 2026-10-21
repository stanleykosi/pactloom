#!/usr/bin/env python3
"""Pure fabricated protocol/source tests. No native code, socket or product run."""
import importlib.util
import pathlib
import socket
import subprocess
import sys
import unittest
from unittest import mock

ROOT = pathlib.Path(__file__).parents[1]
SPEC = importlib.util.spec_from_file_location('private_ci_ui', ROOT / 'ci-ui-controller.py')
C = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = C
with mock.patch.object(socket, 'socketpair') as no_socket, mock.patch.object(subprocess, 'Popen') as no_process:
    SPEC.loader.exec_module(C)
    assert not no_socket.called and not no_process.called


def packet(kind, sequence=0, commit=0, frame=0, width=0, height=0,
           offset=0, length=0, input_sequence=0, status=0, payload=b''):
    return C.HEADER.pack(C.MAGIC, C.VERSION, sequence, kind, status, commit,
                         frame, width, height, offset, length, input_sequence) + payload


class FakeTransport:
    """An in-memory peer, never a socket. It does not prove Weston behavior."""
    def __init__(self):
        self.incoming = [packet(C.READY)]
        self.sent = []
        self.timeouts = []
        self.closed = False
        self.commit, self.frame, self.input_sequence = 1, 1, 0
        self.corrupt = None
        self.read_flags = 0
        self.read_ancillary = []

    def settimeout(self, value):
        self.timeouts.append(value)

    def close(self):
        self.closed = True

    def send(self, raw, flags):
        self.sent.append(raw)
        _, _, seq, op, a, b, reserved1, reserved2 = C.COMMAND.unpack(raw)
        assert reserved1 == reserved2 == 0
        if op in (C.FOCUS, C.MOVE, C.BUTTON, C.KEY, C.SCROLL_DOWN, C.CLOSE_WINDOW):
            self.input_sequence = seq
        if op == C.FRAME:
            self.incoming.append(packet(C.FRAME_BARRIER, seq, self.commit, self.frame,
                                        input_sequence=self.input_sequence))
            self.commit += 1
            self.frame += 1
            self.incoming.append(packet(C.IMAGE, seq, self.commit, self.frame,
                                        C.WIDTH, C.HEIGHT, 0, C.FRAME_BYTES,
                                        self.input_sequence))
            for offset in range(0, C.FRAME_BYTES, C.CHUNK_BYTES):
                size = min(C.CHUNK_BYTES, C.FRAME_BYTES - offset)
                self.incoming.append(packet(C.CHUNK, seq, self.commit, self.frame,
                                            C.WIDTH, C.HEIGHT, offset, size,
                                            self.input_sequence, payload=b'X' * size))
        else:
            self.incoming.append(packet(C.ACK, seq, self.commit, self.frame,
                                        input_sequence=self.input_sequence))
        if self.corrupt:
            self.corrupt(self.incoming)
        return len(raw)

    def recvmsg(self, count, ancbuf, flags):
        assert count in (C.HEADER.size, C.HEADER.size + C.CHUNK_BYTES)
        assert ancbuf == 0
        if not self.incoming:
            raise AssertionError('fabricated response missing')
        return self.incoming.pop(0), self.read_ancillary, self.read_flags, None


class Protocol(unittest.TestCase):
    def setUp(self):
        self.now = [1_000_000_000]
        self.original = self.now[0] + 900_000_000_000
        self.session = self.now[0] + 120_000_000_000
        self.transport = FakeTransport()
        self.controller = C.Controller(self.transport, self.original, self.session,
                                       _clock=lambda: self.now[0])
        self.addCleanup(self.controller.close)
        self.process = mock.Mock(spec=subprocess.Popen)
        self.process.pid = 12345
        self.process.poll.return_value = None

    def bind(self):
        self.controller.wait_ready()
        return self.controller.bind_process(self.process)

    def rejected(self, code, action):
        with self.assertRaises(C.Rejected) as found:
            action()
        self.assertEqual(found.exception.code, code)
        self.assertEqual(str(found.exception), code)
        self.assertTrue(self.transport.closed)

    def test_terminal_cleanup_accepts_only_closed_target_reason(self):
        self.bind()
        self.controller._terminal_close = True
        self.process.returncode = 0
        self.transport.incoming = [packet(C.ERROR, status=4, commit=6), b'']
        self.controller.finish_after_product(1, self.now[0] + 5_000_000_000)
        self.assertTrue(self.transport.closed)

    def test_target_subreason_is_closed_and_preserves_target_class(self):
        compositor = mock.Mock(spec=subprocess.Popen); compositor.poll.return_value = 1
        self.transport.incoming = [packet(C.ERROR, status=4, commit=6)]
        result = self.controller.observe_exited_compositor(compositor)
        self.assertEqual(result, dict(exit_status=1, packet='error', module_error='target', target_reason='unmapped'))

    def test_target_subreason_on_other_error_is_malformed(self):
        compositor = mock.Mock(spec=subprocess.Popen); compositor.poll.return_value = 1
        self.transport.incoming = [packet(C.ERROR, status=5, commit=6)]
        self.assertEqual(self.controller.observe_exited_compositor(compositor),
                         dict(exit_status=1, packet='malformed', module_error=None))

    def test_module_target_tags_cover_each_original_rejection(self):
        source = (ROOT / 'ci-ui-weston-module.c').read_text()
        self.assertEqual(source.count('fail(c, TARGET);'), 1)
        self.assertEqual(source.count('fail_target('), 11)
        for reason in C.TARGET_REASONS[1:]:
            self.assertIn('TARGET_' + reason.upper(), source)
        self.assertIn('if (status == TARGET) h[5] = htole32(c->target_reason);', source)

    def test_exited_compositor_observation_is_bounded_and_never_sends(self):
        self.bind()
        compositor = mock.Mock(spec=subprocess.Popen)
        compositor.poll.return_value = 1
        self.transport.incoming = [packet(C.ERROR, status=4)]
        before = list(self.transport.sent)
        original = self.controller.original_deadline_ns
        self.assertEqual(self.controller.observe_exited_compositor(compositor),
                         dict(exit_status=1, packet='error', module_error='target'))
        self.assertEqual(self.transport.sent, before)
        self.assertEqual(self.controller.original_deadline_ns, original)
        self.assertTrue(self.transport.closed)
        self.assertEqual(self.transport.timeouts[-1], 0.0)

    def test_live_compositor_cannot_be_diagnostically_consumed(self):
        compositor = mock.Mock(spec=subprocess.Popen)
        compositor.poll.return_value = None
        self.rejected('target', lambda: self.controller.observe_exited_compositor(compositor))
        self.assertEqual(self.transport.incoming, [packet(C.READY)])

    def test_exited_compositor_rejects_unbounded_or_nonerror_packet(self):
        compositor = mock.Mock(spec=subprocess.Popen)
        compositor.poll.return_value = -11
        self.transport.incoming = [packet(C.ERROR, status=4, payload=b'private')]
        self.assertEqual(self.controller.observe_exited_compositor(compositor),
                         dict(exit_status=-11, packet='malformed', module_error=None))
        self.assertTrue(self.transport.closed)

    def test_exited_compositor_eof_retains_signal_without_invented_cause(self):
        compositor = mock.Mock(spec=subprocess.Popen)
        compositor.poll.return_value = -9
        self.transport.incoming = [b'']
        self.assertEqual(self.controller.observe_exited_compositor(compositor),
                         dict(exit_status=-9, packet='eof', module_error=None))

    def test_bind_requires_ready_and_real_popen_shape(self):
        self.rejected('target', lambda: self.controller.bind_process(self.process))
        self.assertFalse(self.transport.sent)

    def test_no_numeric_pid_api(self):
        self.controller.wait_ready()
        self.rejected('target', lambda: self.controller.bind_process(12345))
        self.assertFalse(self.transport.sent)

    def test_bind_only_once_even_same_process(self):
        self.bind()
        self.rejected('target', lambda: self.controller.bind_process(self.process))
        self.assertEqual(len(self.transport.sent), 1)

    def test_exited_original_is_terminal_not_rebound(self):
        self.bind()
        self.process.poll.return_value = 0
        self.rejected('target', lambda: self.controller.focus(True))
        self.assertEqual(len(self.transport.sent), 1)

    def test_mutated_process_pid_is_terminal_not_rebound(self):
        self.bind()
        self.process.pid += 1
        self.rejected('target', lambda: self.controller.focus(True))
        self.assertEqual(len(self.transport.sent), 1)

    def test_deadlines_are_supplied_and_not_renewed(self):
        self.bind()
        self.assertEqual(self.controller.original_deadline_ns, self.original)
        self.assertEqual(self.controller.session_deadline_ns, self.session)
        self.now[0] = self.session
        self.rejected('deadline', lambda: self.controller.focus(True))
        self.assertEqual(len(self.transport.sent), 1)

    def test_session_cannot_exceed_original_or_120_seconds(self):
        for original, session in ((10, 11), (self.original, self.session + 1),
                                  (self.original, self.now[0]), (True, True)):
            with self.subTest(original=original, session=session), self.assertRaises(C.Rejected):
                C._deadlines(original, session, self.now[0])

    def test_ready_cannot_repeat(self):
        self.controller.wait_ready()
        self.rejected('protocol', self.controller.wait_ready)

    def test_ready_must_be_exact_hardening_handshake(self):
        self.transport.incoming[0] = packet(C.ACK)
        self.rejected('protocol', self.controller.wait_ready)

    def test_real_input_protocol_and_sequence(self):
        self.bind()
        self.controller.focus(True)
        self.controller.click(10, 20)
        self.controller.type_ascii('/tmp/Public-Owner1.der')
        self.controller.clear_field()
        self.controller.tab()
        self.controller.focus(False)
        self.controller.focus(True)
        commands = [C.COMMAND.unpack(raw) for raw in self.transport.sent]
        self.assertEqual([row[2] for row in commands], list(range(1, len(commands) + 1)))
        self.assertEqual(commands[2][3:6], (C.MOVE, 10, 20))
        self.assertEqual(commands[3][3:6], (C.BUTTON, 1, 0))
        self.assertEqual(commands[4][3:6], (C.BUTTON, 0, 0))
        self.assertTrue(all(len(raw) == 32 for raw in self.transport.sent))

    def test_ascii_encoder_is_closed_and_balanced(self):
        for char in map(chr, range(32, 127)):
            held = set()
            for key, state in C._ascii_events(char):
                if state:
                    self.assertNotIn(key, held)
                    held.add(key)
                else:
                    self.assertIn(key, held)
                    held.remove(key)
            self.assertFalse(held)
        for value in ('\n', '\t', '\0', 'é', 'x' * (C.MAX_TEXT + 1), 42):
            with self.subTest(value=type(value)), self.assertRaises(C.Rejected):
                C._ascii_events(value)

    def test_invalid_text_rejected_before_partial_typing(self):
        self.bind()
        self.rejected('input', lambda: self.controller.type_ascii('valid then\ninvalid'))
        self.assertEqual(len(self.transport.sent), 1)

    def test_coordinates_and_bool_rejected_before_input(self):
        self.bind()
        self.rejected('input', lambda: self.controller.click(True, 3))
        self.assertEqual(len(self.transport.sent), 1)

    def test_whole_gesture_budget_prevents_partial_click(self):
        self.bind()
        self.controller._sequence = C.MAX_COMMANDS - 2
        self.rejected('limit', lambda: self.controller.click(10, 20))
        self.assertEqual(len(self.transport.sent), 1)

    def test_text_budget_checked_before_sending(self):
        self.bind()
        self.controller._sequence = C.MAX_COMMANDS - 3
        self.rejected('limit', lambda: self.controller.type_ascii('AA'))
        self.assertEqual(len(self.transport.sent), 1)

    def test_send_uncertainty_is_terminal_never_retried(self):
        self.bind()
        with mock.patch.object(self.transport, 'send', side_effect=OSError('PRIVATE_SENTINEL')) as sent:
            self.rejected('disconnected', lambda: self.controller.focus(True))
        sent.assert_called_once()

    def test_truncation_or_fd_injection_fails_closed(self):
        self.transport.read_flags = socket.MSG_CTRUNC
        self.rejected('protocol', self.controller.wait_ready)

    def test_short_and_unknown_packets_do_not_leak(self):
        self.transport.incoming[0] = b'PRIVATE_SENTINEL'
        self.rejected('protocol', self.controller.wait_ready)

    def test_unknown_error_enum_rejected(self):
        self.transport.incoming[0] = packet(C.ERROR, status=99)
        self.rejected('protocol', self.controller.wait_ready)

    def test_known_error_enum_is_finite(self):
        self.transport.incoming[0] = packet(C.ERROR, status=4)
        self.rejected('target', self.controller.wait_ready)

    def test_reply_sequence_must_match_exactly(self):
        self.bind()
        self.transport.corrupt = lambda rows: rows.__setitem__(0, packet(C.ACK, 999))
        self.rejected('protocol', lambda: self.controller.focus(True))

    def test_frame_is_real_payload_not_phase_assertion(self):
        self.bind()
        frame = self.controller.observe(after_commit=0)
        self.assertEqual((frame.width, frame.height), (1280, 800))
        self.assertEqual(len(frame.bgra()), C.FRAME_BYTES)
        self.assertEqual(frame.bgra()[:4], b'XXXX')
        self.assertGreater(frame.receipt.commit, 0)
        self.assertGreater(frame.receipt.frame, 0)
        self.assertNotIn('XXXX', repr(frame))
        frame.wipe()
        self.assertFalse(any(self.controller._pixels))
        with self.assertRaises(C.Rejected):
            frame.bgra()

    def test_only_one_live_borrowed_snapshot(self):
        self.bind()
        first = self.controller.observe(after_commit=0)
        second = self.controller.observe()
        self.assertIs(first._pixels, second._pixels)
        with self.assertRaises(C.Rejected):
            first.bgra()
        self.controller.close()
        self.assertFalse(any(second._pixels))

    def test_frame_cannot_reuse_previous_commit_barrier(self):
        self.bind()
        self.controller.observe(after_commit=0)
        self.rejected('limit', lambda: self.controller.observe(after_commit=0))

    def test_frame_cannot_relax_last_input_commit_barrier(self):
        self.bind()
        self.controller.focus(True)
        self.rejected('limit', lambda: self.controller.observe(after_commit=0))

    def test_frame_rejects_reordered_or_incomplete_chunks(self):
        self.bind()
        self.transport.corrupt = lambda rows: rows.pop(1)
        self.rejected('protocol', lambda: self.controller.observe(after_commit=0))
        self.assertFalse(any(self.controller._pixels))

    def test_frame_rejects_stale_commit_even_with_new_frame(self):
        self.bind()
        self.controller.focus(True)
        def stale(rows):
            old = list(C.HEADER.unpack(rows[1]))
            old[5] = 1
            rows[1] = C.HEADER.pack(*old)
        self.transport.corrupt = stale
        self.rejected('protocol', self.controller.observe)

    def test_frame_snapshot_rejects_midstream_counter_change(self):
        self.bind()
        def changed(rows):
            h = list(C.HEADER.unpack(rows[2][:C.HEADER.size]))
            h[5] += 1
            rows[2] = C.HEADER.pack(*h) + rows[2][C.HEADER.size:]
        self.transport.corrupt = changed
        self.rejected('protocol', lambda: self.controller.observe(after_commit=0))

    def test_capture_budget_cannot_be_reset(self):
        self.bind()
        self.controller._captures = C.MAX_FRAMES
        self.rejected('limit', self.controller.observe)
        self.assertEqual(len(self.transport.sent), 1)

    def test_environment_control_values_forbidden_in_product(self):
        C.check_product_environment({'WAYLAND_DISPLAY': 'wayland-0'})
        for name in (*C.CONTROL_ENV, 'CI_UI_FUTURE_CONTROL'):
            with self.assertRaises(C.Rejected):
                C.check_product_environment({name: 'PRIVATE_SENTINEL'})

    def test_close_has_no_implicit_product_or_compositor_action(self):
        self.bind()
        self.controller.close()
        self.assertEqual(len(self.transport.sent), 1)
        self.process.terminate.assert_not_called()
        self.process.kill.assert_not_called()


class ReceiptBarrier(unittest.TestCase):
    setUp = Protocol.setUp
    bind = Protocol.bind
    rejected = Protocol.rejected
    # In-memory transport only. These additions exercise the closed new ops.
    def test_frame_uses_actual_receipt_barrier(self):
        self.bind()
        self.transport.commit, self.transport.frame = 10, 20
        frame = self.controller.observe(after_commit=0)
        self.assertEqual((frame.barrier.commit, frame.barrier.frame), (10, 20))
        self.assertEqual((frame.receipt.commit, frame.receipt.frame), (11, 21))

    def test_duplicate_frame_barrier_is_not_an_image(self):
        self.bind()
        self.transport.corrupt = lambda rows: rows.insert(1, rows[0])
        self.rejected('protocol', self.controller.observe)

    def test_ordinary_ack_cannot_replace_frame_barrier(self):
        self.bind()
        def wrong(rows):
            header = list(C.HEADER.unpack(rows[0])); header[3] = C.ACK
            rows[0] = C.HEADER.pack(*header)
        self.transport.corrupt = wrong
        self.rejected('protocol', self.controller.observe)

    def test_same_frame_as_actual_barrier_refused(self):
        self.bind()
        def stale(rows):
            barrier = C.HEADER.unpack(rows[0]); header = list(C.HEADER.unpack(rows[1]))
            header[6] = barrier[6]; rows[1] = C.HEADER.pack(*header)
        self.transport.corrupt = stale
        self.rejected('protocol', self.controller.observe)

    def test_fixed_scroll_operation(self):
        self.bind(); self.controller.focus(True)
        self.controller.scroll_down(100, 200)
        operations = [C.COMMAND.unpack(raw)[3:6] for raw in self.transport.sent[-2:]]
        self.assertEqual(operations, [(C.MOVE, 100, 200), (C.SCROLL_DOWN, 0, 0)])

    def test_scroll_coordinates_are_closed(self):
        self.bind()
        self.rejected('input', lambda: self.controller.scroll_down(-1, 0))

    def test_terminal_close_does_not_reap_or_allow_later_input(self):
        self.bind()
        def exited_after_send(rows):
            self.process.poll.return_value = 0
        self.transport.corrupt = exited_after_send
        self.controller.close_window()
        self.assertFalse(self.transport.closed)  # EOF must not rescue the product.
        self.assertEqual(C.COMMAND.unpack(self.transport.sent[-1])[3], C.CLOSE_WINDOW)
        self.process.wait.assert_not_called()
        self.rejected('target', lambda: self.controller.focus(True))


    def test_terminal_widget_release_keeps_child_unreaped_and_edge_open(self):
        self.bind()
        def exit_only_after_release(rows):
            _, _, _, op, value, *_ = C.COMMAND.unpack(self.transport.sent[-1])
            if op == C.BUTTON and value == 0: self.process.poll.return_value = 0
        self.transport.corrupt = exit_only_after_release
        self.controller.terminal_click(100, 200)
        self.assertTrue(self.controller._terminal_close)
        self.assertFalse(self.transport.closed)
        self.process.wait.assert_not_called()
        operations = [C.COMMAND.unpack(raw)[3:6] for raw in self.transport.sent[-3:]]
        self.assertEqual(operations, [(C.MOVE, 100, 200), (C.BUTTON, 1, 0), (C.BUTTON, 0, 0)])

    def test_terminal_capture_is_forbidden(self):
        self.bind(); self.controller.close_window()
        self.rejected('limit', self.controller.observe)

    def test_terminal_target_error_and_exact_eof_after_product_wait(self):
        self.bind(); self.controller.close_window(); self.process.returncode = 0
        self.transport.incoming = [packet(C.ERROR, status=4), b'']
        self.controller.finish_after_product(1, self.now[0] + 5_000_000_000)
        self.assertTrue(self.transport.closed)

    def test_terminal_clean_sigterm_exit_with_eof(self):
        self.bind(); self.controller.close_window(); self.process.returncode = 0
        self.transport.incoming = [b'']
        self.controller.finish_after_product(0, self.now[0] + 5_000_000_000)
        self.assertTrue(self.transport.closed)

    def test_exit_one_without_exact_target_is_not_cleanup_success(self):
        self.bind(); self.controller.close_window(); self.process.returncode = 0
        self.transport.incoming = [b'']
        self.rejected('target', lambda: self.controller.finish_after_product(1, self.now[0] + 5_000_000_000))

    def test_other_terminal_error_and_trailing_packets_are_refused(self):
        for packets in ([packet(C.ERROR, status=1)], [packet(C.ERROR, sequence=9, status=4)],
                        [packet(C.ERROR, status=4), packet(C.ACK)],
                        [packet(C.ERROR, status=4), packet(C.ERROR, status=4)]):
            with self.subTest(packets=len(packets)):
                self.setUp(); self.bind(); self.controller.close_window(); self.process.returncode = 0
                self.transport.incoming = list(packets)
                self.rejected('protocol', lambda: self.controller.finish_after_product(1, self.now[0] + 5_000_000_000))

    def test_terminal_cleanup_cannot_replace_actual_product_wait(self):
        self.bind(); self.controller.close_window(); self.process.returncode = None
        self.rejected('target', lambda: self.controller.finish_after_product(0, self.now[0] + 5_000_000_000))

    def test_terminal_cleanup_signal_status_is_refused(self):
        self.bind(); self.controller.close_window(); self.process.returncode = 0
        self.rejected('target', lambda: self.controller.finish_after_product(-15, self.now[0] + 5_000_000_000))


    def test_terminal_reads_share_one_original_cleanup_deadline(self):
        self.bind(); self.controller.close_window(); self.process.returncode = 0
        deadline = self.now[0] + 5_000_000_000
        replies = [packet(C.ERROR, status=4), b'']
        def slow_reads(*args):
            self.now[0] += 3_000_000_000
            return replies.pop(0), [], 0, None
        self.transport.recvmsg = slow_reads
        self.rejected('deadline', lambda: self.controller.finish_after_product(1, deadline))
        self.assertEqual(self.transport.timeouts[-2:], [5., 2.])

    def test_terminal_cleanup_cannot_extend_original_scope(self):
        self.bind(); self.controller.close_window(); self.process.returncode = 0
        self.rejected('target', lambda: self.controller.finish_after_product(0, self.original + 1))


class SourceBoundary(unittest.TestCase):
    def test_hardening_checks_already_unprivileged_identity_only(self):
        libc = mock.Mock()
        libc.prctl.side_effect = (1, 0, 0)
        with mock.patch.object(C.os, 'getresuid', return_value=(10001,) * 3), \
                mock.patch.object(C.os, 'getresgid', return_value=(10001,) * 3), \
                mock.patch.object(C.os, 'getgroups', return_value=[]), \
                mock.patch.object(C.resource, 'setrlimit') as limits, \
                mock.patch.object(C.ctypes, 'CDLL', return_value=libc):
            C.harden_process()
        self.assertEqual(libc.prctl.call_args_list,
                         [mock.call(39, 0, 0, 0, 0), mock.call(4, 0, 0, 0, 0),
                          mock.call(3, 0, 0, 0, 0)])
        limits.assert_called_once_with(C.resource.RLIMIT_CORE, (0, 0))

    def test_wrong_uid_never_attempts_privilege_change_or_channel(self):
        with mock.patch.object(C.os, 'getresuid', return_value=(0, 0, 0)), \
                mock.patch.object(C.ctypes, 'CDLL') as native, \
                mock.patch.object(C.socket, 'socketpair') as sockets, \
                self.assertRaises(C.Rejected):
            C.harden_process()
        native.assert_not_called()
        sockets.assert_not_called()

    def test_module_uses_exact_real_path_and_no_control_global(self):
        text = (ROOT / 'ci-ui-weston-module.c').read_text()
        self.assertIn('#include <libweston/desktop.h>', text)
        for call in ('notify_motion(', 'notify_button(', 'notify_key(',
                     'notify_keyboard_focus_in(', 'notify_keyboard_focus_out(',
                     'weston_seat_set_keyboard_focus(', 'wl_client_get_credentials(',
                     'weston_desktop_surface_get_app_id(', '->read_pixels('):
            self.assertIn(call, text)
        for forbidden in ('wl_global_create(', 'system(', 'popen(', 'execve(',
                          'open(', 'fopen(', 'NativeDecision', 'wl_resource_set_implementation('):
            self.assertNotIn(forbidden, text)
        self.assertIn('"org.wholepact.CoordinatorDelivery"', text)
        self.assertEqual(C.APP_ID, 'org.wholepact.CoordinatorDelivery')
        self.assertIn('weston_compositor_exit_with_code', text)
        self.assertIn('PR_SET_DUMPABLE', text)
        self.assertIn('kind == IMAGE || kind == CHUNK', text)

    def test_actual_geometry_and_receipt_barrier_are_source_bound(self):
        text = (ROOT / 'ci-ui-weston-module.c').read_text()
        for token in ('weston_coord_surface_to_global', 'view->transform.dirty',
                      'pixman_region32_contains_rectangle', 'PIXMAN_REGION_IN',
                      'const int xs[4]', 'const int ys[4]', 'view_covers_output(node)',
                      'FRAME_BARRIER', 'a > c->target->commits ? a : c->target->commits',
                      'b > c->frames ? b : c->frames', 'notify_axis(',
                      'weston_desktop_surface_close('):
            self.assertIn(token, text)
        frame = text[text.index('if (op == FRAME)'):text.index('if (op == FOCUS')]
        self.assertNotIn('ack(c)', frame)
        self.assertNotIn('c->pending = c->pending_op = 0', frame)

    def test_cross_language_protocol_constants_and_memory_ceiling(self):
        text = (ROOT / 'ci-ui-weston-module.c').read_text()
        for name, value in [('WIDTH', C.WIDTH), ('HEIGHT', C.HEIGHT),
                            ('MAX_COMMANDS', C.MAX_COMMANDS), ('MAX_FRAMES', C.MAX_FRAMES),
                            ('MAX_COMMITS', C.MAX_COMMITS), ('CHUNK_BYTES', C.CHUNK_BYTES)]:
            self.assertIn(f'#define {name} {value}u', text)
        self.assertLessEqual(C.FRAME_BYTES, 4 * 1024 * 1024)
        self.assertEqual(C.COMMAND.size, 32)
        self.assertEqual(C.HEADER.size, 48)


if __name__ == '__main__':
    unittest.main()
