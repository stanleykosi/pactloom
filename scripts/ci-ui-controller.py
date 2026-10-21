#!/usr/bin/env python3
"""Private CI-only native-input transport. Importing this module does nothing.

Not an executable runner, product API, approval facade, or human-consent claim.
The reviewed supervisor owns the one fixture, original deadline, environment,
Popen instances, natural product disposal evidence, and container removal.

Integration order, ONLY in the final reviewed disposable CI:
  1. make_channel(original_deadline_ns, session_deadline_ns) hardens supervisor.
  2. Spawn official Weston headless/Pixman/kiosk-shell with only compositor_end
     in pass_fds and compositor_environment additions. Close compositor_end in
     supervisor, then controller.wait_ready(). Module has now hardened itself.
  3. Spawn the unchanged actual coordinator with close_fds=True, pass_fds=(),
     a fresh explicit product environment without ANY CI_UI_* variables, and
     normal Wayland display access only. bind_process(actual_popen) once.
  4. Use genuine widgets through click/type_ascii/clear_field/focus. Observe
     actual committed+rendered pixels privately; never publish pixels, paths,
     PIDs, hashes of pixels, raw protocol, or raw exception/tool output.
  5. Wipe snapshots, independently establish natural product cleanup, then
     remove compositor/controller and entire container. Transport teardown is
     not product cleanup evidence. Target loss is terminal and never rebinds.

The absolute original ceiling is supplied, never minted/reset here. Each
separate session has its own supplied <=120s sub-budget bounded by that ceiling.
Pure tests use fake transports/processes; no test starts a socket or product.
"""

import ctypes
import dataclasses
import os
import resource
import socket
import struct
import subprocess
import time

MAGIC = 0x31554943
VERSION = 1
WIDTH, HEIGHT = 1280, 800
FRAME_BYTES = WIDTH * HEIGHT * 4
CHUNK_BYTES = 32768
MAX_COMMANDS = 65536
MAX_FRAMES = 32
MAX_COMMITS = 262144
MAX_TEXT = 16384
SESSION_NS = 120_000_000_000
APP_ID = 'org.wholepact.CoordinatorDelivery'
COMMAND = struct.Struct('<8I')
HEADER = struct.Struct('<12I')
BIND, FOCUS, MOVE, BUTTON, KEY, FRAME, STOP, SCROLL_DOWN, CLOSE_WINDOW = range(1, 10)
ACK, IMAGE, CHUNK, ERROR, READY, FRAME_BARRIER = range(1, 7)
ERRORS = ('ok', 'protocol', 'deadline', 'limit', 'target', 'input',
          'output', 'readback', 'disconnected', 'internal')
CONTROL_ENV = ('CI_UI_CONTROL_FD', 'CI_UI_ORIGINAL_DEADLINE_NS',
               'CI_UI_SESSION_DEADLINE_NS')


class Rejected(Exception):
    """Finite, value-free failure. Do not attach raw packets/paths/commands."""
    def __init__(self, code):
        self.code = code if code in ERRORS[1:] else 'internal'
        super().__init__(self.code)


@dataclasses.dataclass(frozen=True)
class Receipt:
    sequence: int
    commit: int
    frame: int
    input_sequence: int


class PrivateFrame:
    """One borrowed BGRA snapshot; repr contains no pixels or target identity.

    Valid only until wipe() or the next observe()/close(). The caller must use
    actual pixels for its private source-backed UI checks; counters alone are
    NOT evidence of any presented string, phase, approval, or financial effect.
    """
    __slots__ = ('receipt', 'barrier', 'width', 'height', '_pixels', '_valid')

    def __init__(self, receipt, pixels, barrier):
        self.receipt = receipt
        self.barrier = barrier
        self.width, self.height = WIDTH, HEIGHT
        self._pixels = pixels
        self._valid = True

    def __repr__(self):
        return '<PrivateFrame redacted>'

    def bgra(self):
        if not self._valid:
            raise Rejected('protocol')
        return memoryview(self._pixels).toreadonly()

    def wipe(self):
        if self._valid:
            _wipe(self._pixels)
            self._valid = False

    def __enter__(self):
        if not self._valid:
            raise Rejected('protocol')
        return self

    def __exit__(self, *_):
        self.wipe()


def _wipe(buffer):
    # Bounded chunks avoid allocating a second full-size frame to zero it.
    zeros = b'\0' * CHUNK_BYTES
    for start in range(0, len(buffer), CHUNK_BYTES):
        size = min(CHUNK_BYTES, len(buffer) - start)
        buffer[start:start + size] = zeros[:size]


def _deadlines(original, session, now):
    if (type(original) is not int or type(session) is not int or
            not 0 < now < session <= original < 2**64 or session - now > SESSION_NS):
        raise Rejected('deadline')


def harden_process():
    """Call before making the control edge or spawning an untrusted product."""
    try:
        if (os.getresuid() != (10001, 10001, 10001) or
                os.getresgid() != (10001, 10001, 10001) or os.getgroups()):
            raise Rejected('internal')
        resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
        libc = ctypes.CDLL(None, use_errno=True)
        # Linux PR_SET_DUMPABLE=4 and PR_GET_DUMPABLE=3. No credentials here.
        # PR_GET_NO_NEW_PRIVS=39 checks the already-established confinement.
        if (libc.prctl(39, 0, 0, 0, 0) != 1 or
                libc.prctl(4, 0, 0, 0, 0) != 0 or libc.prctl(3, 0, 0, 0, 0) != 0):
            raise Rejected('internal')
    except (OSError, ValueError):
        raise Rejected('internal') from None


def make_channel(original_deadline_ns, session_deadline_ns):
    """Return (controller, compositor endpoint, exact env additions).

    No runner is invoked and no product is spawned by this helper. Caller must
    close the returned compositor endpoint in the supervisor immediately after
    its explicit Weston Popen. Product spawning must wait for wait_ready().
    """
    _deadlines(original_deadline_ns, session_deadline_ns, time.monotonic_ns())
    harden_process()
    left = right = None
    try:
        left, right = socket.socketpair(socket.AF_UNIX,
                                       socket.SOCK_SEQPACKET | socket.SOCK_CLOEXEC)
        left.set_inheritable(False)
        right.set_inheritable(False)
        env = dict(zip(CONTROL_ENV, (str(right.fileno()), str(original_deadline_ns),
                                   str(session_deadline_ns))))
        controller = Controller(left, original_deadline_ns, session_deadline_ns)
        return controller, right, env
    except BaseException:
        if left is not None:
            left.close()
        if right is not None:
            right.close()
        raise


def check_product_environment(environment):
    """Supplement, not replace, Popen close_fds=True and pass_fds=()."""
    if any(key.startswith('CI_UI_') for key in environment):
        raise Rejected('protocol')


def _ascii_events(text):
    """Closed US evdev mapping. Reject the entire value before any input."""
    if type(text) is not str or len(text) > MAX_TEXT:
        raise Rejected('input')
    rows = [('1234567890', 2), ('qwertyuiop', 16), ('asdfghjkl', 30),
            ('zxcvbnm', 44)]
    mapping = {char: first + offset for row, first in rows
               for offset, char in enumerate(row)}
    mapping.update({'-': 12, '=': 13, '[': 26, ']': 27, ';': 39, "'": 40,
                    '`': 41, '\\': 43, ',': 51, '.': 52, '/': 53, ' ': 57})
    shifted = dict(zip('!@#$%^&*()_+{}:"~|<>?', '1234567890-=[];\'`\\,./'))
    result = []
    for char in text:
        shift = 'A' <= char <= 'Z' or char in shifted
        base = char.lower() if 'A' <= char <= 'Z' else shifted.get(char, char)
        if base not in mapping:
            raise Rejected('input')
        if shift:
            result.append((42, 1))
        result.extend(((mapping[base], 1), (mapping[base], 0)))
        if shift:
            result.append((42, 0))
    return tuple(result)


class Controller:
    """One closed session, one Popen target, one live private image buffer."""

    def __init__(self, transport, original_deadline_ns, session_deadline_ns,
                 *, _clock=time.monotonic_ns):
        _deadlines(original_deadline_ns, session_deadline_ns, _clock())
        self._socket = transport
        self._clock = _clock
        self._original = original_deadline_ns
        self._session = session_deadline_ns
        self._sequence = self._captures = 0
        self._ready = self._bound = self._closed = False
        self._bind_attempted = False
        self._terminal_close = False
        self._process = None
        self._bound_pid = None
        self._receipt = Receipt(0, 0, 0, 0)
        self._last_input_commit = 0
        self._last_observed_commit = 0
        self._last_observed_frame = 0
        self._pixels = bytearray(FRAME_BYTES)
        self._frame = None

    def __repr__(self):
        return '<Controller private-native-input>'

    @property
    def original_deadline_ns(self):
        return self._original

    @property
    def session_deadline_ns(self):
        return self._session

    @property
    def receipt(self):
        return self._receipt

    def _reject(self, code):
        self.close()
        raise Rejected(code)

    def _remaining(self):
        if self._closed:
            raise Rejected('disconnected')
        left = min(self._original, self._session) - self._clock()
        if left <= 0:
            self._reject('deadline')
        if self._process is not None:
            if self._process.pid != self._bound_pid or (not self._terminal_close and self._process.poll() is not None):
                self._reject('target')
        return left / 1_000_000_000

    def _read(self):
        while True:
            self._socket.settimeout(min(.05, self._remaining()))
            try:
                packet, ancillary, flags, _ = self._socket.recvmsg(
                    HEADER.size + CHUNK_BYTES, 0, socket.MSG_CMSG_CLOEXEC)
            except socket.timeout:
                continue
            except OSError:
                self._reject('disconnected')
            self._remaining()
            if ancillary or flags & (socket.MSG_TRUNC | socket.MSG_CTRUNC):
                self._reject('protocol')
            if len(packet) < HEADER.size:
                self._reject('protocol')
            h = HEADER.unpack_from(packet)
            if h[0:2] != (MAGIC, VERSION):
                self._reject('protocol')
            if h[3] == ERROR:
                if len(packet) != HEADER.size or not 0 < h[4] < len(ERRORS):
                    self._reject('protocol')
                self._reject(ERRORS[h[4]])
            if h[2] != self._sequence or h[4] != 0:
                self._reject('protocol')
            if (not 0 <= h[5] <= MAX_COMMITS or not 0 <= h[6] <= MAX_COMMITS or
                    h[11] > self._sequence):
                self._reject('protocol')
            return h, packet[HEADER.size:]

    def wait_ready(self):
        """MUST precede product spawn: confirms module hardening after exec."""
        if self._ready or self._sequence:
            self._reject('protocol')
        h, payload = self._read()
        if h != (MAGIC, VERSION, 0, READY, 0, 0, 0, 0, 0, 0, 0, 0) or payload:
            self._reject('protocol')
        self._ready = True

    def _send(self, op, a=0, b=0):
        if not self._ready or self._sequence >= MAX_COMMANDS:
            self._reject('limit')
        self._remaining()
        self._sequence += 1
        packet = COMMAND.pack(MAGIC, VERSION, self._sequence, op, a, b, 0, 0)
        self._socket.settimeout(self._remaining())
        try:
            # One atomic seqpacket send. Never retry uncertain input delivery.
            if self._socket.send(packet, socket.MSG_NOSIGNAL) != COMMAND.size:
                self._reject('disconnected')
        except OSError:
            self._reject('disconnected')

    def _ack(self, op):
        h, payload = self._read()
        expected_input = self._sequence if op in (FOCUS, MOVE, BUTTON, KEY, SCROLL_DOWN, CLOSE_WINDOW) else self._receipt.input_sequence
        if (h[3] != ACK or payload or h[7:11] != (0, 0, 0, 0) or
                h[5] < self._receipt.commit or h[6] < self._receipt.frame or
                h[11] != expected_input):
            self._reject('protocol')
        self._receipt = Receipt(h[2], h[5], h[6], h[11])
        if op in (FOCUS, MOVE, BUTTON, KEY, SCROLL_DOWN, CLOSE_WINDOW):
            self._last_input_commit = h[5]
        return self._receipt

    def _command(self, op, a=0, b=0):
        if not self._bound or self._terminal_close:
            self._reject('target')
        self._send(op, a, b)
        return self._ack(op)

    def bind_process(self, process):
        if self._bind_attempted or not self._ready:
            self._reject('target')
        self._bind_attempted = True
        # No arbitrary numeric PID API. The supervisor's actual spawned Popen
        # stays retained and is checked before/after every protocol operation.
        if (not isinstance(process, subprocess.Popen) or process.poll() is not None or
                type(process.pid) is not int or not 1 < process.pid < 2**31 or
                process.pid == os.getpid()):
            self._reject('target')
        self._process = process
        self._bound_pid = process.pid
        self._send(BIND, process.pid)
        receipt = self._ack(BIND)
        if receipt.commit == 0:
            self._reject('target')
        self._bound = True
        return receipt

    def focus(self, enabled):
        if type(enabled) is not bool:
            self._reject('input')
        return self._command(FOCUS, int(enabled))

    def click(self, x, y):
        if type(x) is not int or type(y) is not int or not (0 <= x < WIDTH and 0 <= y < HEIGHT):
            self._reject('input')
        self._budget(3)
        self._command(MOVE, x, y)
        self._command(BUTTON, 1)
        return self._command(BUTTON, 0)

    def scroll_down(self, x, y):
        """One fixed real wheel event, never an arbitrary axis value."""
        if type(x) is not int or type(y) is not int or not (0 <= x < WIDTH and 0 <= y < HEIGHT):
            self._reject('input')
        self._budget(2)
        self._command(MOVE, x, y)
        return self._command(SCROLL_DOWN)

    def close_window(self):
        """One terminal compositor-close request for credential-free smoke.

        Keep the actual child UNREAPED after sending the close. It can naturally
        exit before its ACK arrives, but its retained PID cannot be recycled.
        No subsequent input/capture is allowed on this permanently closed edge.
        """
        if not self._bound or self._terminal_close:
            self._reject('target')
        self._send(CLOSE_WINDOW)
        self._terminal_close = True
        receipt = self._ack(CLOSE_WINDOW)
        self.close()
        return receipt

    def _budget(self, count):
        if self._sequence + count > MAX_COMMANDS:
            self._reject('limit')

    def type_ascii(self, public_value):
        """Only existing paths and inert/public request values, never secrets."""
        try:
            events = _ascii_events(public_value)
        except Rejected:
            self._reject('input')
        self._budget(len(events))
        for key, pressed in events:
            self._command(KEY, key, pressed)
        return self._receipt

    def clear_field(self):
        self._budget(6)
        for key, pressed in ((29, 1), (30, 1), (30, 0), (29, 0), (14, 1), (14, 0)):
            self._command(KEY, key, pressed)
        return self._receipt

    def tab(self):
        self._budget(2)
        self._command(KEY, 15, 1)
        return self._command(KEY, 15, 0)

    def observe(self, *, after_commit=None):
        """Require a newer bound-surface commit AND a newer rendered frame.

        The distinct FRAME_BARRIER reply records the actual request-receipt
        counters. A later repaint of an already committed buffer cannot pass.
        Initial capture may explicitly use after_commit=0. After input the
        default is the commit counter acknowledged at its last event. Callers
        may demand a stricter counter but cannot relax that input barrier.
        """
        barrier = max(self._last_input_commit, self._last_observed_commit)
        minimum = barrier if after_commit is None else after_commit
        if (type(minimum) is not int or minimum < barrier or
                minimum > self._receipt.commit or self._captures >= MAX_FRAMES or
                not self._bound):
            self._reject('limit')
        if self._frame is not None:
            self._frame.wipe()
        self._captures += 1
        self._send(FRAME, minimum, self._last_observed_frame)
        h, payload = self._read()
        if (h[3] != FRAME_BARRIER or payload or h[7:11] != (0, 0, 0, 0) or
                h[5] < minimum or h[6] < self._last_observed_frame or
                h[5] < self._receipt.commit or h[6] < self._receipt.frame or
                h[11] != self._receipt.input_sequence):
            self._reject('protocol')
        barrier = Receipt(h[2], h[5], h[6], h[11])
        h, payload = self._read()
        if (h[3] != IMAGE or payload or h[7:11] != (WIDTH, HEIGHT, 0, FRAME_BYTES) or
                h[5] <= barrier.commit or h[6] <= barrier.frame or
                h[5] < self._receipt.commit or h[6] < self._receipt.frame or
                h[11] != self._receipt.input_sequence):
            self._reject('protocol')
        image_header = h
        offset = 0
        while offset < FRAME_BYTES:
            h, payload = self._read()
            length = min(CHUNK_BYTES, FRAME_BYTES - offset)
            if (h[3] != CHUNK or h[5:9] != image_header[5:9] or
                    h[9:11] != (offset, length) or len(payload) != length or
                    h[11] != image_header[11]):
                self._reject('protocol')
            self._pixels[offset:offset + length] = payload
            offset += length
        self._receipt = Receipt(image_header[2], image_header[5], image_header[6], image_header[11])
        self._last_observed_frame = self._receipt.frame
        self._last_observed_commit = self._receipt.commit
        self._frame = PrivateFrame(self._receipt, self._pixels, barrier)
        return self._frame

    def stop(self):
        """Compositor teardown only. Never count this as natural UI cleanup."""
        if self._bound:
            self._command(STOP)
        self.close()

    def close(self):
        if self._closed:
            return
        self._closed = True
        if self._frame is not None:
            self._frame.wipe()
        _wipe(self._pixels)
        self._socket.close()


if __name__ == '__main__':
    # This source is a library, not authorization or an alternate local runner.
    raise SystemExit('ci_ui_controller_is_not_a_runner')
