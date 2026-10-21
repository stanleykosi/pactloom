#!/usr/bin/env python3
"""CI-only one-shot setup/custody edge. Import is inert; no product authority.

New recovery revision. The original bytes were lost, so every parser and runtime
join below requires fresh source review. This wrapper is never a local runner.
"""
import array
import ctypes
import fcntl
import importlib.util
import json
import os
import pathlib
import re
import resource
import selectors
import socket
import stat
import struct
import subprocess
import sys
import time

HERE = pathlib.Path(__file__).parent
SPEC = importlib.util.spec_from_file_location('ci_ui_output', HERE / 'ci-ui-output.py')
P = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(P)
UID = 10001
CAP_SETUP = 0xc0
MAX_HANDOFF = 2 * 1024 * 1024
MAX_PACKET = 4096
MAX_OUTPUT = 512 * 1024
BASE = pathlib.Path('/ci-fixture')
SELECTOR_PREFIX = ('host::manual_enrollment::command::roster_publication_v2::'
    'sequential_construction_v3::qualification::durable_proposal_v1::pristine_coordinator_v1::')
SETUP_SELECTOR = SELECTOR_PREFIX + 'coordinator_pristine_three_account_source_for_ui'
READY = b'CI_UI_FIXTURE_READY version=1 accounts=3 target_head=4 process_cleanup=true'
FORM_KEYS = frozenset(('endpoint', 'server_name', 'witness_id', 'pinned_server_certificate_digest',
    'network_profile_id', 'expected_account_id', 'owner_certificate_der_hex', 'storage_key_file',
    'server_certificate_der', 'server_private_key_pkcs8_der', 'trusted_client_root_der', 'request_json'))
OWNER_KEYS = frozenset(('certificate_der', 'private_key_pkcs8_der', 'trusted_server_root_der'))
CUSTODY_KEYS = frozenset(('version', 'kind', 'root_path', 'home_path', 'root_device', 'root_inode',
    'home_device', 'home_inode', 'original_monotonic_cutoff_ns'))
ERROR_KEYS = frozenset(('version', 'kind', 'stage', 'code', 'source_boundary', 'source_outcome'))


class Rejected(Exception):
    def __init__(self, code):
        self.code = code if type(code) is str and code in P.CODES else 'invalid_record'
        super().__init__(self.code)


def require(ok, code):
    if not ok:
        raise Rejected(code)


def number(value, low, high):
    return P.number(value, low, high)


def loads(raw, limit=MAX_PACKET):
    try:
        return P.loads(raw, limit)
    except P.Rejected as error:
        raise Rejected(error.code) from None


def identity():
    require(os.getresuid() == (UID,) * 3 and os.getresgid() == (UID,) * 3 and
            os.getgroups() == [], 'runtime_identity')
    fields = dict(line.split(':', 1) for line in pathlib.Path('/proc/self/status').read_text().splitlines()
                  if ':' in line)
    require(fields['Uid'].split() == [str(UID)] * 4 and
            fields['Gid'].split() == [str(UID)] * 4, 'runtime_identity')
    require(all(int(fields[k], 16) == 0 for k in ('CapInh', 'CapPrm', 'CapEff', 'CapAmb')) and
            int(fields['CapBnd'], 16) == CAP_SETUP and fields['NoNewPrivs'].strip() == '1',
            'runtime_caps')
    require(len(list(pathlib.Path('/proc/self/task').iterdir())) == 1, 'runtime_thread')
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    libc = ctypes.CDLL(None, use_errno=True)
    require(libc.prctl(4, 0, 0, 0, 0) == 0 and libc.prctl(3, 0, 0, 0, 0) == 0,
            'runtime_dumpable')


def namespace_empty_except(allowed):
    actual = {int(path.name) for path in pathlib.Path('/proc').iterdir() if path.name.isdecimal()}
    require(actual == set(allowed), 'namespace_not_empty')


def canonical_child(path, parent, *, filesystem=True):
    require(type(path) is str and 1 <= len(path) <= 1024 and
            all(32 <= ord(c) < 127 and c != ':' for c in path), 'custody_path')
    candidate = pathlib.Path(path)
    require(candidate.is_absolute() and str(candidate) == path and '..' not in candidate.parts and
            candidate.parent == parent, 'custody_path')
    if filesystem:
        require(os.path.realpath(path) == path, 'custody_path')
    return candidate


def directory(path):
    fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        meta = os.fstat(fd)
        require(stat.S_ISDIR(meta.st_mode) and meta.st_uid == UID and meta.st_gid == UID and
                stat.S_IMODE(meta.st_mode) == 0o700, 'custody_identity')
        require(os.readlink(f'/proc/self/fd/{fd}') == str(path), 'custody_path')
        return fd
    except BaseException:
        os.close(fd)
        raise


def read_private(path, limit):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    with os.fdopen(fd, 'rb') as stream:
        meta = os.fstat(stream.fileno())
        require(stat.S_ISREG(meta.st_mode) and meta.st_uid == UID and meta.st_gid == UID and
                stat.S_IMODE(meta.st_mode) == 0o600 and meta.st_nlink == 1 and
                0 < meta.st_size <= limit, 'custody_identity')
        raw = stream.read(limit + 1)
        require(len(raw) == meta.st_size, 'custody_identity')
    return raw


def private_handoff(original):
    """Wrapper UID only. Root never reads the descriptor or private key bytes."""
    value = loads(read_private(BASE / 'handoff.json', MAX_HANDOFF), MAX_HANDOFF)
    require(type(value) is dict and set(value) == {'version', 'root_path', 'root_device',
        'root_inode', 'original_monotonic_cutoff_ns', 'fixture'} and
        number(value['version'], 1, 1) and value['original_monotonic_cutoff_ns'] == original,
        'custody_packet')
    root = canonical_child(value['root_path'], BASE)
    require(re.fullmatch(r'ui-[A-Za-z0-9_-]{1,64}', root.name) is not None, 'custody_path')
    fixture = value['fixture']
    require(type(fixture) is dict and set(fixture) == {'version', 'installation', 'home_path',
        'form', 'owner_client', 'accounts'} and number(fixture['version'], 1, 1), 'custody_packet')
    home = canonical_child(fixture['home_path'], root)
    require(type(fixture['installation']) is list and 0 < len(fixture['installation']) <= 16384 and
            all(number(n, 0, 255) for n in fixture['installation']), 'custody_packet')
    form, owner, accounts = fixture['form'], fixture['owner_client'], fixture['accounts']
    require(type(form) is dict and set(form) == FORM_KEYS and
            all(type(v) is str and 0 < len(v) <= MAX_HANDOFF for v in form.values()) and
            type(owner) is dict and set(owner) == OWNER_KEYS and
            all(type(v) is str and 0 < len(v) <= 1024 for v in owner.values()), 'custody_packet')
    require(type(accounts) is list and len(accounts) == 3 and all(type(a) is dict and set(a) == {
        'account_id', 'head', 'original_signed_birth', 'original_source_commitment'} for a in accounts),
        'custody_packet')
    ids = [a['account_id'] for a in accounts]
    require(all(type(i) is str and 0 < len(i) <= 1024 for i in ids) and len(set(ids)) == 3 and
            form['expected_account_id'] in ids, 'custody_packet')
    paths = ((form['storage_key_file'], 'synthetic-namespace.key'),
        (form['server_certificate_der'], 'server.der'),
        (form['server_private_key_pkcs8_der'], 'server.pk8'),
        (form['trusted_client_root_der'], 'ca.der'), (owner['certificate_der'], 'owner.der'),
        (owner['private_key_pkcs8_der'], 'owner.pk8'), (owner['trusted_server_root_der'], 'ca.der'))
    for raw, name in paths:
        require(raw == str(home / name), 'custody_path')
        meta = os.stat(raw, follow_symlinks=False)
        require(stat.S_ISREG(meta.st_mode) and meta.st_uid == UID and meta.st_gid == UID and
                meta.st_nlink == 1 and stat.S_IMODE(meta.st_mode) == 0o600, 'custody_identity')
    fds = []
    try:
        fds = [directory(root)]
        fds.append(directory(home))
        root_meta, home_meta = (os.fstat(fd) for fd in fds)
        require(number(value['root_device'], 0, (1 << 64) - 1) and
                number(value['root_inode'], 1, (1 << 64) - 1) and
                (root_meta.st_dev, root_meta.st_ino) == (value['root_device'], value['root_inode']),
                'custody_identity')
        record = dict(version=1, kind='custody', root_path=str(root), home_path=str(home),
            root_device=root_meta.st_dev, root_inode=root_meta.st_ino,
            home_device=home_meta.st_dev, home_inode=home_meta.st_ino,
            original_monotonic_cutoff_ns=original)
        return record, fds
    except BaseException:
        for fd in fds:
            os.close(fd)
        raise


class FirstFailure:
    def __init__(self):
        self.value = None

    def note(self, stage, code, boundary=None, outcome=None, observation=None):
        candidate = P.failure('fixture', stage, code, source_boundary=boundary, source_outcome=outcome,
                              setup_observation=observation)
        if self.value is None:
            self.value = candidate
        return self.value


def setup_line(line, first):
    prefix = ('test ' + SETUP_SELECTOR + ' ... ').encode('ascii')
    if line.startswith(prefix):
        line = line[len(prefix):]
    line = line.removesuffix(b'\r')
    if line.startswith(b'CI_UI_SETUP_FAILURE'):
        match = re.fullmatch(rb'CI_UI_SETUP_FAILURE boundary=([A-Za-z][A-Za-z0-9]*) outcome=([A-Za-z][A-Za-z0-9]*)', line)
        require(match is not None, 'setup_output')
        boundary, outcome = (v.decode('ascii') for v in match.groups())
        require(boundary in P.SETUP_BOUNDARIES and outcome in P.SETUP_OUTCOMES, 'setup_output')
        first.note('setup', 'setup_source', boundary, outcome)
        raise Rejected('setup_source')
    if line.startswith(b'CI_UI_FIXTURE_READY'):
        require(line == READY, 'setup_output')
        return 'ready'
    if line == b'running 1 test':
        return 'running'
    if line.startswith(b'test result:'):
        require(re.fullmatch(rb'test result: ok\. 1 passed; 0 failed; 0 ignored; [0-9]+ measured; [0-9]+ filtered out; finished in [0-9.]+s', line) is not None, 'setup_count')
        return 'result'
    return None


def validate_setup_result(status, counts, first):
    # Closed numeric supervision evidence only. Never expose arbitrary child
    # stdout, paths, panic text, keys or fixture data.
    require(type(counts) is dict and set(counts) == {'ready', 'running', 'result'} and
            all(number(counts[key], 0, 1) for key in counts) and
            number(status, -64, 255), 'setup_output')
    if status != 0 or counts != {'ready': 1, 'running': 1, 'result': 1}:
        first.note('setup', 'setup_status', observation=dict(exit_status=status, **counts))
        raise Rejected('setup_status')


def run_setup(original, first):
    require(time.monotonic_ns() < original, 'original_deadline')
    command = ['/opt/ci-ui/pristine-setup', '--exact', SETUP_SELECTOR,
               '--ignored', '--nocapture', '--test-threads=1']
    process = subprocess.Popen(command, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT, close_fds=True, pass_fds=(), start_new_session=True,
        env={'PATH': '/usr/bin:/bin', 'TMPDIR': str(BASE), 'RUST_BACKTRACE': '0',
             'WHOLEPACT_TEST_ONLY_PRIVATE_WORKFLOW_CUTOFF_NS': str(original)})
    selector = selectors.DefaultSelector()
    pending, total, counts = bytearray(), 0, {'ready': 0, 'running': 0, 'result': 0}
    try:
        selector.register(process.stdout, selectors.EVENT_READ)
        while selector.get_map():
            require(time.monotonic_ns() < original, 'original_deadline')
            for key, _ in selector.select(.05):
                chunk = os.read(key.fileobj.fileno(), 16384)
                if not chunk:
                    selector.unregister(key.fileobj)
                    continue
                total += len(chunk)
                require(total <= MAX_OUTPUT, 'output_limit')
                pending.extend(chunk)
                while b'\n' in pending:
                    line, _, rest = pending.partition(b'\n'); pending[:] = rest
                    kind = setup_line(bytes(line), first)
                    if kind:
                        counts[kind] += 1
                        require(counts[kind] == 1, 'setup_count')
        require(not pending or setup_line(bytes(pending), first) is None, 'setup_output')
        status = process.wait(timeout=max(.001, (original - time.monotonic_ns()) / 1e9))
        validate_setup_result(status, counts, first)
        namespace_empty_except((1, os.getpid()))
    except BaseException as error:
        first.note('setup', error.code if isinstance(error, (Rejected, P.Rejected)) else 'internal')
        # Failure remains a failure. Whole-container ownership, not this direct
        # child rescue, is the authoritative cleanup boundary after an error.
        if process.poll() is None:
            try:
                process.kill()
            except OSError:
                pass
        raise
    finally:
        try:
            selector.close()
        finally:
            process.stdout.close()


def validate_received(value, fds, original):
    require(type(value) is dict and set(value) == CUSTODY_KEYS and
            number(value['version'], 1, 1) and value['kind'] == 'custody' and
            value['original_monotonic_cutoff_ns'] == original, 'custody_packet')
    require(len(fds) == 2 and len(set(fds)) == 2 and all(fd > 2 for fd in fds), 'custody_rights')
    root = canonical_child(value['root_path'], BASE, filesystem=False)
    require(re.fullmatch(r'ui-[A-Za-z0-9_-]{1,64}', root.name) is not None, 'custody_path')
    home = canonical_child(value['home_path'], root, filesystem=False)
    for fd, path, prefix in zip(fds, (root, home), ('root', 'home')):
        flags = fcntl.fcntl(fd, fcntl.F_GETFL)
        require(flags & os.O_ACCMODE == os.O_RDONLY and flags & os.O_DIRECTORY and
                not flags & getattr(os, 'O_PATH', 0) and
                fcntl.fcntl(fd, fcntl.F_GETFD) & fcntl.FD_CLOEXEC, 'custody_rights')
        meta = os.fstat(fd)
        require(stat.S_ISDIR(meta.st_mode) and meta.st_uid == UID and meta.st_gid == UID and
                stat.S_IMODE(meta.st_mode) == 0o700 and
                number(value[prefix + '_device'], 0, (1 << 64) - 1) and
                number(value[prefix + '_inode'], 1, (1 << 64) - 1) and
                (meta.st_dev, meta.st_ino) == (value[prefix + '_device'], value[prefix + '_inode']),
                'custody_identity')
        require(os.readlink(f'/proc/self/fd/{fd}') == str(path), 'custody_path')
    return value


def validate_error_packet(value):
    require(type(value) is dict and set(value) in (ERROR_KEYS, ERROR_KEYS | {'setup_observation'}) and
            number(value['version'], 1, 1) and value['kind'] == 'error', 'custody_packet')
    projected = P.failure('fixture', value['stage'], value['code'],
        source_boundary=value['source_boundary'], source_outcome=value['source_outcome'])
    if 'setup_observation' in value:
        projected['setup_observation'] = value['setup_observation']
    return P.validate_failure(projected, 'fixture')


def error_packet(value):
    P.validate_failure(value, 'fixture')
    packet = dict(version=1, kind='error', stage=value['stage'], code=value['code'],
        source_boundary=value['source_boundary'], source_outcome=value['source_outcome'])
    if 'setup_observation' in value:
        packet['setup_observation'] = value['setup_observation']
    validate_error_packet(packet)
    return packet


def receive_custody(edge, wrapper, original):
    # Root must also set PASSCRED before spawn, before a packet can queue.
    edge.setsockopt(socket.SOL_SOCKET, socket.SO_PASSCRED, 1)
    edge.settimeout(max(.001, (original - time.monotonic_ns()) / 1e9))
    fds = []
    try:
        data, controls, flags, _ = edge.recvmsg(MAX_PACKET + 1,
            socket.CMSG_SPACE(struct.calcsize('3i')) + socket.CMSG_SPACE(8),
            socket.MSG_CMSG_CLOEXEC)
        credentials, rights_records, invalid = [], 0, False
        for level, kind, raw in controls:
            if level == socket.SOL_SOCKET and kind == socket.SCM_RIGHTS:
                rights_records += 1
                ints = array.array('i')
                # Close every complete installed right even if ancillary bytes
                # are malformed. Never reject before collecting those rights.
                ints.frombytes(raw[:len(raw) - len(raw) % ints.itemsize])
                fds.extend(ints.tolist())
                invalid |= len(raw) % ints.itemsize != 0
            elif level == socket.SOL_SOCKET and kind == socket.SCM_CREDENTIALS:
                if len(raw) == struct.calcsize('3i'):
                    credentials.append(struct.unpack('3i', raw))
                else:
                    invalid = True
            else:
                invalid = True
        require(not invalid and not flags & (socket.MSG_TRUNC | socket.MSG_CTRUNC) and
                0 < len(data) <= MAX_PACKET, 'custody_packet')
        require(wrapper.poll() is None and credentials == [(wrapper.pid, UID, UID)],
                'custody_credentials')
        value = loads(data)
        if type(value) is dict and value.get('kind') == 'error':
            require(not fds and rights_records == 0, 'custody_packet')
            validate_error_packet(value)
            return value, []
        require(rights_records == 1, 'custody_rights')
        validate_received(value, fds, original)
        result = fds; fds = []
        return value, result
    finally:
        for fd in set(fds):
            try:
                os.close(fd)
            except OSError:
                pass


def wrapper_main(fd, original, started):
    edge = socket.socket(fileno=fd)
    edge.set_inheritable(False)
    first, fds, attempted = FirstFailure(), [], False
    try:
        require(edge.family == socket.AF_UNIX and edge.type & 0xf == socket.SOCK_SEQPACKET,
                'custody_packet')
        identity()
        require(number(original, 1, (1 << 63) - 1) and number(started, 1, original) and
                original - started == 900_000_000_000 and time.monotonic_ns() < original,
                'cutoff_mismatch')
        run_setup(original, first)
        value, fds = private_handoff(original)
        namespace_empty_except((1, os.getpid()))
        raw = json.dumps(value, separators=(',', ':')).encode('ascii')
        require(len(raw) <= MAX_PACKET and time.monotonic_ns() < original, 'custody_packet')
        edge.settimeout(max(.001, min(5., (original - time.monotonic_ns()) / 1e9)))
        attempted = True  # uncertain send is never retried with another packet
        sent = edge.sendmsg([raw], [(socket.SOL_SOCKET, socket.SCM_RIGHTS, array.array('i', fds))])
        require(sent == len(raw), 'custody_packet')
        edge.settimeout(max(.001, (original - time.monotonic_ns()) / 1e9))
        require(edge.recv(5) == b'ACK1', 'custody_ack')
        return 0
    except BaseException as error:
        code = error.code if isinstance(error, (Rejected, P.Rejected)) else 'internal'
        first.note('identity' if code.startswith('runtime_') else 'setup', code)
        if not attempted:
            value = first.value
            packet = error_packet(value)
            attempted = True
            try:
                # A short supervision-only ACK grace keeps this exact sender
                # unreaped for credential authentication; it never runs more
                # fixture work or extends the original request ceiling.
                edge.settimeout(5.)
                edge.send(json.dumps(packet, separators=(',', ':')).encode('ascii'))
                edge.recv(5)
            except OSError:
                pass
        return 1
    finally:
        for value in fds:
            os.close(value)
        edge.close()


if __name__ == '__main__':
    # Only the trusted root PID1 launcher supplies this inherited private edge.
    try:
        require(len(sys.argv) == 4 and all(re.fullmatch('[0-9]+', v) for v in sys.argv[1:]), 'custody_packet')
        values = [int(v) for v in sys.argv[1:]]
        require(values[0] > 2, 'custody_packet')
        status = wrapper_main(*values)
    except BaseException:
        status = 1
    sys.exit(status)
