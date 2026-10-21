#!/usr/bin/env python3
"""Disposable UI CI PID1, new recovery revision. Import performs no setup.

Only SETUID/GID exist during fixture custody. Root does not read credential
bytes, although SETUID technically permits impersonation. All product/display
work follows the verified permanent UID drop. This entrypoint is solely for the
reviewed disposable CI image; the outer exact-source gate owns whole-container
removal, and no inner success alone claims that removal.
"""
import ctypes
import hashlib
import importlib.util
import json
import os
import pathlib
import re
import resource
import socket
import stat
import subprocess
import sys
import time

ROOT = pathlib.Path(__file__).parent
SPEC = importlib.util.spec_from_file_location('ci_ui_setup_wrapper', ROOT / 'ci-ui-setup-wrapper.py')
S = importlib.util.module_from_spec(SPEC); sys.modules[SPEC.name] = S; SPEC.loader.exec_module(S)
P = S.P
LOCK_SHA256 = '2c86592b3b931cb88024205be851caafaa2845f4620d6a950d43d760d94e8127'
FILES = frozenset(('ci-ui-container.py', 'ci-ui-setup-wrapper.py', 'ci-ui-controller.py',
                  'ci-ui-output.py', 'coordinator-production', 'coordinator-observed',
                  'pristine-setup', 'ci-ui-weston-module.so'))
ARTIFACTS = frozenset(('coordinator-production', 'coordinator-observed', 'pristine-setup'))
ACCOUNT = pathlib.Path('/run/ci-account')
PASSWD = ACCOUNT / 'passwd'
PIN_DIR = pathlib.Path('/etc/wholepact')
PIN = PIN_DIR / 'financial-coordinator-common-image-v1.json'
require = S.require


def root_context():
    require(os.getpid() == 1 and os.getresuid() == (0, 0, 0) and
            os.getresgid() == (0, 0, 0), 'root_identity')
    require(len(list(pathlib.Path('/proc/self/task').iterdir())) == 1, 'root_thread')
    fields = dict(line.split(':', 1) for line in pathlib.Path('/proc/self/status').read_text().splitlines()
                  if ':' in line)
    require(fields['Uid'].split() == ['0'] * 4 and fields['Gid'].split() == ['0'] * 4,
            'root_identity')
    require(all(int(fields[key], 16) == S.CAP_SETUP for key in ('CapEff', 'CapPrm', 'CapBnd')) and
            all(int(fields[key], 16) == 0 for key in ('CapInh', 'CapAmb')) and
            fields['NoNewPrivs'].strip() == '1', 'root_caps')
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    libc = ctypes.CDLL(None, use_errno=True)
    require(libc.prctl(4, 0, 0, 0, 0) == 0 and libc.prctl(3, 0, 0, 0, 0) == 0,
            'root_dumpable')
    os.umask(0o077)
    os.environ.clear()


def root_directory(path, code):
    meta = path.stat(follow_symlinks=False)
    require(stat.S_ISDIR(meta.st_mode) and meta.st_uid == 0 and meta.st_gid == 0 and
            stat.S_IMODE(meta.st_mode) == 0o755, code)


def require_image_file_identity(name, meta, pin):
    require(name in FILES, 'image_file')
    # The synthetic provider pins its own UID-owned executable. This exact
    # exception is not an installed production-provider trust change.
    owner = S.UID if name == 'pristine-setup' else 0
    require(stat.S_ISREG(meta.st_mode) and meta.st_uid == owner and meta.st_gid == owner and
            meta.st_nlink == 1 and meta.st_size == pin['size'] and
            stat.S_IMODE(meta.st_mode) == (0o555 if name in ARTIFACTS else 0o444), 'image_file')


def image_manifest():
    require(ROOT == pathlib.Path('/opt/ci-ui'), 'image_directory')
    # Even the UID-owned synthetic executable cannot be chmod'ed or replaced.
    require(bool(os.statvfs(ROOT).f_flag & os.ST_RDONLY), 'image_directory')
    for directory in (pathlib.Path('/'), pathlib.Path('/opt'), ROOT):
        root_directory(directory, 'image_directory')
    fd = os.open(ROOT / 'manifest.json', os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    with os.fdopen(fd, 'rb') as stream:
        meta = os.fstat(stream.fileno())
        require(stat.S_ISREG(meta.st_mode) and meta.st_uid == 0 and meta.st_gid == 0 and
                meta.st_nlink == 1 and stat.S_IMODE(meta.st_mode) == 0o444 and
                0 < meta.st_size <= 8192, 'manifest')
        raw = stream.read(8193)
        require(len(raw) == meta.st_size, 'manifest')
    value = S.loads(raw, 8192)
    require(type(value) is dict and set(value) == {'schema_version', 'package_lock_sha256', 'files'} and
            type(value['schema_version']) is int and value['schema_version'] == 1 and
            value['package_lock_sha256'] == LOCK_SHA256 and type(value['files']) is dict and
            set(value['files']) == FILES, 'manifest')
    actual = {}
    for name, pin in value['files'].items():
        require(type(pin) is dict and set(pin) == {'size', 'sha256'} and
                S.number(pin['size'], 1, 512 * 1024 * 1024) and type(pin['sha256']) is str and
                re.fullmatch('[0-9a-f]{64}', pin['sha256']) is not None, 'manifest')
        fd = os.open(ROOT / name, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
        with os.fdopen(fd, 'rb') as stream:
            meta = os.fstat(stream.fileno())
            require_image_file_identity(name, meta, pin)
            require(hashlib.file_digest(stream, 'sha256').hexdigest() == pin['sha256'], 'image_hash')
            actual[name] = (meta, pin['sha256'])
    return actual


def passwd_bytes(base, home):
    """Pure exact base preservation plus one locked, non-login disposable UID."""
    require(type(base) is bytes and 0 < len(base) <= 65536 and base.endswith(b'\n'), 'passwd_base')
    require(type(home) is str and home.startswith('/') and not home.startswith('//') and 0 < len(home) <= 1024 and
            all(32 <= ord(char) < 127 and char != ':' for char in home) and
            str(pathlib.Path(home)) == home and '..' not in pathlib.Path(home).parts, 'passwd_home')
    try:
        text = base.decode('ascii')
    except UnicodeError:
        raise S.Rejected('passwd_base') from None
    names, uids = set(), set()
    for line in text.splitlines():
        fields = line.split(':')
        require(len(fields) == 7 and fields[0] and fields[2].isdecimal() and fields[3].isdecimal()
                and '\0' not in line and fields[0] not in names, 'passwd_base')
        names.add(fields[0]); uids.add(int(fields[2]))
    require('wholepact-ci' not in names and S.UID not in uids, 'passwd_base')
    return base + f'wholepact-ci:x:{S.UID}:{S.UID}:Disposable CI fixture:{home}:/usr/sbin/nologin\n'.encode('ascii')


def write_passwd(base, home, *, final):
    root_directory(pathlib.Path('/run'), 'passwd_path')
    root_directory(ACCOUNT, 'passwd_path')
    link = pathlib.Path('/etc/passwd')
    meta = link.lstat()
    require(stat.S_ISLNK(meta.st_mode) and meta.st_uid == 0 and meta.st_gid == 0 and
            os.readlink(link) == str(PASSWD), 'passwd_path')
    data = passwd_bytes(base, home)
    if final:
        old = PASSWD.stat(follow_symlinks=False)
        require(stat.S_ISREG(old.st_mode) and old.st_uid == 0 and old.st_gid == 0 and
                old.st_nlink == 1 and stat.S_IMODE(old.st_mode) == 0o444 and
                PASSWD.read_bytes() == passwd_bytes(base, '/nonexistent'), 'passwd_owner')
    else:
        require(not PASSWD.exists(), 'passwd_owner')
    temporary = ACCOUNT / ('passwd.final' if final else 'passwd.initial')
    fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o444)
    os.fchmod(fd, 0o444)
    with os.fdopen(fd, 'wb') as stream:
        stream.write(data); stream.flush(); os.fsync(stream.fileno())
    os.replace(temporary, PASSWD)


def create_pin(artifact, manifest):
    require(artifact in ('coordinator-production', 'coordinator-observed'), 'pin_file')
    root_directory(pathlib.Path('/etc'), 'pin_directory')
    root_directory(PIN_DIR, 'pin_directory')
    meta, digest = manifest[artifact]
    current = (ROOT / artifact).stat(follow_symlinks=False)
    require((current.st_dev, current.st_ino, current.st_size) ==
            (meta.st_dev, meta.st_ino, meta.st_size), 'image_file')
    value = dict(schema_version=1, profile='financial-coordinator-common-image-linux-v1',
                 executable_device=meta.st_dev, executable_inode=meta.st_ino,
                 executable_size=meta.st_size, executable_sha256=digest)
    fd = os.open(PIN, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o444)
    os.fchmod(fd, 0o444)
    with os.fdopen(fd, 'wb') as stream:
        stream.write(json.dumps(value, separators=(',', ':'), sort_keys=True).encode('ascii'))
    current = PIN.stat(follow_symlinks=False)
    require(stat.S_ISREG(current.st_mode) and current.st_uid == 0 and current.st_gid == 0 and
            current.st_nlink == 1 and stat.S_IMODE(current.st_mode) == 0o444, 'pin_file')


def fixture_tmpfs():
    for path in (pathlib.Path('/ci-fixture'), pathlib.Path('/run/wholepact-delivery-evidence'),
                 pathlib.Path('/run/ci-wayland')):
        meta = path.stat(follow_symlinks=False)
        require(stat.S_ISDIR(meta.st_mode) and meta.st_uid == S.UID and meta.st_gid == S.UID and
                stat.S_IMODE(meta.st_mode) == 0o700, 'fixture_tmpfs')


def setup_one_fixture(original, started, report_failure):
    """One actual setup only. Returned directory metadata is not authority."""
    fixture_tmpfs(); S.namespace_empty_except((1,))
    left, right = socket.socketpair(socket.AF_UNIX, socket.SOCK_SEQPACKET | socket.SOCK_CLOEXEC)
    fds, failing = [], False
    try:
        left.setsockopt(socket.SOL_SOCKET, socket.SO_PASSCRED, 1)  # before spawn
        left.set_inheritable(False); right.set_inheritable(False)
        process = subprocess.Popen(['/usr/local/bin/python3', '-I', '-B',
            str(ROOT / 'ci-ui-setup-wrapper.py'), str(right.fileno()), str(original), str(started)],
            stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            user=S.UID, group=S.UID, extra_groups=[], start_new_session=True,
            env={}, close_fds=True, pass_fds=(right.fileno(),))
        right.close()
        require(os.getpgid(process.pid) == process.pid, 'setup_process')
        value, fds = S.receive_custody(left, process, original)
        if value['kind'] == 'error':
            # Retain the original observation before even ACK/reap can fail.
            report_failure(P.failure('fixture', value['stage'], value['code'],
                source_boundary=value['source_boundary'], source_outcome=value['source_outcome'],
                setup_observation=value.get('setup_observation')))
            require(process.poll() is None, 'custody_credentials')
            left.settimeout(5.); require(left.send(b'ACK1') == 4, 'custody_ack')
            process.wait(timeout=5.)
            raise S.Rejected(value['code'])
        S.namespace_empty_except((1, process.pid))
        S.validate_received(value, fds, original)
        require(time.monotonic_ns() < original, 'original_deadline')
        require(process.poll() is None, 'custody_credentials')  # immediately before ACK
        left.settimeout(max(.001, min(5., (original - time.monotonic_ns()) / 1e9)))
        require(left.send(b'ACK1') == 4, 'custody_ack')
        require(process.wait(timeout=max(.001, min(5., (original - time.monotonic_ns()) / 1e9))) == 0,
                'setup_status')
        S.namespace_empty_except((1,))
        require(time.monotonic_ns() < original, 'original_deadline')
        return value
    except BaseException as error:
        failing = True
        code = error.code if isinstance(error, (S.Rejected, P.Rejected)) else 'setup_process'
        report_failure(P.failure('fixture', 'custody', code))
        raise
    finally:
        # All copies close before passwd finalization, pin, or any product launch.
        # Do not lose the actual first refusal to a later close exception.
        close_failed = False
        for fd in fds:
            try:
                os.close(fd)
            except OSError:
                close_failed = True
        for edge in (left, right):
            try:
                edge.close()
            except OSError:
                close_failed = True
        if close_failed:
            report_failure(P.failure('fixture', 'drain', 'cleanup_failed'))
            if not failing:
                raise S.Rejected('cleanup_failed')


def base_passwd():
    fd = os.open(ROOT / 'base-passwd', os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    with os.fdopen(fd, 'rb') as stream:
        meta = os.fstat(stream.fileno())
        require(stat.S_ISREG(meta.st_mode) and meta.st_uid == 0 and meta.st_gid == 0 and
                stat.S_IMODE(meta.st_mode) == 0o444 and meta.st_nlink == 1 and
                0 < meta.st_size <= 65536, 'passwd_base')
        data = stream.read(65537)
        require(len(data) == meta.st_size, 'passwd_base')
    return data


def prepare_runtime(source_backed, report_failure, timing=None):
    root_context(); manifest = image_manifest(); fixture_tmpfs()
    base = base_passwd(); write_passwd(base, '/nonexistent', final=False)
    started = time.monotonic_ns(); original = started + 900_000_000_000
    if timing is not None: timing['started'] = started
    custody = None
    if source_backed:
        custody = setup_one_fixture(original, started, report_failure)
        write_passwd(base, custody['home_path'], final=True)
    create_pin('coordinator-observed' if source_backed else 'coordinator-production', manifest)
    S.namespace_empty_except((1,))
    os.setgroups([]); os.setresgid(S.UID, S.UID, S.UID); os.setresuid(S.UID, S.UID, S.UID)
    S.identity()
    return original, started, custody


# New integrated source revision. Runtime activation remains a separate review.
import dataclasses
import math
import selectors

CSPEC = importlib.util.spec_from_file_location('ci_ui_controller', ROOT / 'ci-ui-controller.py')
D = importlib.util.module_from_spec(CSPEC); sys.modules[CSPEC.name] = D; CSPEC.loader.exec_module(D)
EVIDENCE = pathlib.Path('/run/wholepact-delivery-evidence')
WAYLAND = pathlib.Path('/run/ci-wayland')
FIELDS = (('Endpoint', 'endpoint'), ('ServerName', 'server_name'), ('WitnessId', 'witness_id'),
    ('ServerCertificateDigest', 'pinned_server_certificate_digest'), ('NetworkProfile', 'network_profile_id'),
    ('AccountId', 'expected_account_id'), ('StorageKeyPath', 'storage_key_file'),
    ('ServerCertificatePath', 'server_certificate_der'), ('ServerPrivateKeyPath', 'server_private_key_pkcs8_der'),
    ('ClientRootPath', 'trusted_client_root_der'), ('OwnerCertificate', 'owner_certificate_der_hex'),
    ('Request', 'request_json'))
OWNER_SELECTOR = S.SELECTOR_PREFIX.rsplit('pristine_coordinator_v1::', 1)[0] + \
    'pristine_owner_client_v1::coordinator_pristine_owner_same_stream_one_append'
WESTON = ('/usr/bin/weston', '--backend=headless', '--renderer=pixman', '--shell=kiosk-shell.so',
    '--width=1280', '--height=800', '--scale=1', '--transform=normal', '--socket=wayland-ui',
    '--idle-time=0', '--no-config', '--modules=/opt/ci-ui/ci-ui-weston-module.so')


def original_facts(raw, original):
    """The retained serde_json bytes are hashed, never reserialized as a request.

    Authority lib.rs::digest uses SHA256(domain || NUL || serde_json bytes), and
    the maintained custody exporter writes this exact serde_json request once.
    No field value here grants source/append authority; actual W opens originals.
    """
    value = S.loads(raw, S.MAX_HANDOFF)
    require(value['original_monotonic_cutoff_ns'] == original, 'original_deadline')
    form = value['fixture']['form']
    request_bytes = form['request_json'].encode('ascii')
    request = S.loads(request_bytes, 65536)
    owner = bytes.fromhex(form['owner_certificate_der_hex'])
    facts = dict(descriptor_digest=hashlib.sha256(raw).hexdigest(),
        request_commitment=hashlib.sha256(b'wholepact:durable-delivery-admission-preparation:v3\0' + request_bytes).hexdigest(),
        cutoff_ns=original, account_id=request['account_id'], operation_id=request['operation_id'],
        expected_head=request['expected_head'], owner_certificate_digest=hashlib.sha256(owner).hexdigest())
    require(request['account_id'] == form['expected_account_id'] and request['expected_head']['sequence'] == 4,
            'original_request')
    return value, facts


def physical_region(snapshot, widget):
    r = widget['rect']; scale = snapshot['pixels_per_point']
    region = {k: (math.floor(v * scale) if k in ('left', 'top') else math.ceil(v * scale)) for k, v in r.items()}
    require(0 <= region['left'] < region['right'] <= D.WIDTH and
            0 <= region['top'] < region['bottom'] <= D.HEIGHT, 'display_geometry')
    return region


def center(snapshot, widget):
    r = physical_region(snapshot, widget)
    return ((r['left'] + r['right']) // 2, (r['top'] + r['bottom']) // 2)


def pixel_digest(pixels, region):
    require(len(pixels) == D.FRAME_BYTES, 'source_paint')
    digest = hashlib.sha256()
    for y in range(region['top'], region['bottom']):
        digest.update(pixels[(y * D.WIDTH + region['left']) * 4:(y * D.WIDTH + region['right']) * 4])
    return digest.hexdigest()


class FirstRuntimeFailure:
    def __init__(self, mode):
        self.mode, self.value, self.stage, self.case = mode, None, 'root', None
        self.runtime_context = None
        self._context_active = False

    def note(self, value):
        if self._context_active: return
        if self.value is None and self.runtime_context is not None:
            try:
                self._context_active = True
                enriched = dict(value, runtime_observation=self.runtime_context())
                P.validate_failure(enriched, self.mode)
                value = enriched
            except Exception:
                pass  # original first failure remains authoritative
            finally:
                self._context_active = False
        P.validate_failure(value, self.mode)
        if self.value is None:
            self.value = value
            print('CI_UI_FAILURE ' + json.dumps(value, separators=(',', ':')), flush=True)

    def error(self, error, records=()):
        candidate = getattr(error, 'failure', None)
        if candidate is None:
            code = getattr(error, 'code', 'internal')
            if isinstance(error, D.Rejected):
                code = {'deadline': 'display_deadline', 'target': 'display_binding', 'input': 'input_bounds',
                    'limit': 'input_budget', 'output': 'display_geometry', 'readback': 'display_frame'}.get(code, 'display_protocol')
            code = code if code in P.CODES else 'internal'
            detail = None
            if code in ('source_failure', 'uncertain_effect') and records:
                try: detail = P.delivery_first_failure(records)
                except P.Rejected: pass
            candidate = P.failure(self.mode, self.stage, code, self.case,
                delivery_stage=None if detail is None else detail['stage'],
                delivery_class=None if detail is None else detail['class'])
        self.note(candidate)


class ObserverFiles:
    """Secure append-only private collection. Live incomplete suffixes wait only.

    Final evidence never omits a suffix, file, or closure. Polling an incomplete
    observation does not repeat input, preparation, TLS, or any product action.
    """
    def __init__(self):
        self.prefixes, self.identities = {}, {}

    def read(self, *, final=False):
        entries = list(EVIDENCE.iterdir())
        require(len(entries) <= 32, 'record_count')
        require(set(self.prefixes) <= {p.name for p in entries}, 'record_file')
        files, total = {}, 0
        for path in sorted(entries):
            require(re.fullmatch(r'[1-9][0-9]{0,9}\.jsonl', path.name) is not None, 'record_file')
            fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
            with os.fdopen(fd, 'rb') as stream:
                before = os.fstat(stream.fileno())
                require(stat.S_ISREG(before.st_mode) and before.st_uid == S.UID and before.st_gid == S.UID and
                    before.st_nlink == 1 and stat.S_IMODE(before.st_mode) == 0o600 and
                    0 <= before.st_size <= 256 * 1024, 'record_file')
                raw = stream.read(256 * 1024 + 1)
                after = os.fstat(stream.fileno())
            require(len(raw) <= 256 * 1024 and after.st_nlink == 1, 'record_overflow')
            identity = (before.st_dev, before.st_ino)
            require(self.identities.get(path.name, identity) == identity, 'record_file')
            self.identities[path.name] = identity
            previous = self.prefixes.get(path.name, b'')
            require(raw.startswith(previous), 'record_sequence')
            if final:
                require(before.st_size == after.st_size == len(raw) and raw.endswith(b'\n'), 'record_incomplete')
                complete = raw
            else:
                complete = raw[:raw.rfind(b'\n') + 1]
            self.prefixes[path.name] = complete
            total += len(raw); require(total <= 4 * 1024 * 1024, 'record_overflow')
            if complete: files[path.name] = complete
        if not files:
            require(not final, 'record_incomplete'); return []
        return P.load_observer_files(files)

    def erase_after_case(self):
        # Only called after natural product drain, completed audit and oracle.
        for name, identity in self.identities.items():
            path = EVIDENCE / name; meta = path.stat(follow_symlinks=False)
            require((meta.st_dev, meta.st_ino) == identity, 'record_file')
            path.unlink()
        require(not list(EVIDENCE.iterdir()), 'record_file')


class LibSelector:
    """One fixed ignored real LIB test; never retries and never exports raw PTY."""
    def __init__(self, selector, original, reporter, *, owner=False):
        allowed = (OWNER_SELECTOR, S.SELECTOR_PREFIX + 'coordinator_pristine_originals_after_cancel_or_blur',
                   S.SELECTOR_PREFIX + 'coordinator_originals_after_one_exact_append')
        require(selector in allowed and (selector == OWNER_SELECTOR) is owner, 'setup_process')
        self.selector, self.original, self.reporter, self.owner = selector, original, reporter, owner
        self.pending, self.total, self.counts, self.result = bytearray(), 0, {'running': 0, 'result': 0, 'marker': 0}, None
        self.failure_seen = False
        self.process = subprocess.Popen([str(ROOT / 'pristine-setup'), '--exact', selector,
            '--ignored', '--nocapture', '--test-threads=1'], stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT, env={'PATH': '/usr/bin:/bin',
            'TMPDIR': '/ci-fixture', 'RUST_BACKTRACE': '0',
            'WHOLEPACT_TEST_ONLY_PRIVATE_WORKFLOW_CUTOFF_NS': str(original)},
            close_fds=True, pass_fds=(), start_new_session=True)
        self.poller = selectors.DefaultSelector(); self.poller.register(self.process.stdout, selectors.EVENT_READ)

    def line(self, line):
        prefix = ('test ' + self.selector + ' ... ').encode('ascii')
        if line.startswith(prefix): line = line[len(prefix):]
        kind = None  # Direct Linux pipe: do not normalize typed failure grammar.
        if line.startswith(b'CI_UI_OWNER_CLIENT_FAILURE'):
            require(self.owner and not self.failure_seen, 'setup_output')
            self.failure_seen = True
            code = P.parse_owner_client_failure(line)
            self.reporter.note(P.failure('fixture', 'append', code, 'append'))
            raise S.Rejected(code)
        if line.startswith(b'CI_UI_SETUP_FAILURE'):
            first = S.FirstFailure()
            try: S.setup_line(line, first)
            except S.Rejected:
                if first.value:
                    failure = dict(first.value); failure['case'] = self.reporter.case; failure['stage'] = 'audit'
                    self.reporter.note(failure)
                raise
        marker = b'CI_UI_OWNER_CLIENT ' if self.owner else b'CI_UI_FIXTURE_AUDIT '
        if line.startswith(marker):
            require(self.result is None, 'setup_output')
            self.result = P.loads(line[len(marker):], limit=4096); kind = 'marker'
        elif line.startswith(b'CI_UI_'):
            raise S.Rejected('setup_output')
        elif line == b'running 1 test': kind = 'running'
        elif line.startswith(b'test result:'):
            require(re.fullmatch(rb'test result: ok\. 1 passed; 0 failed; 0 ignored; [0-9]+ measured; [0-9]+ filtered out; finished in [0-9.]+s', line) is not None,
                    'setup_count'); kind = 'result'
        if kind:
            self.counts[kind] += 1; require(self.counts[kind] == 1, 'setup_count')

    def pump(self):
        require(time.monotonic_ns() < self.original, 'original_deadline')
        for key, _ in self.poller.select(0):
            chunk = os.read(key.fileobj.fileno(), 16384)
            if not chunk:
                self.poller.unregister(key.fileobj); continue
            self.total += len(chunk); require(self.total <= S.MAX_OUTPUT, 'output_limit')
            self.pending.extend(chunk)
            while b'\n' in self.pending:
                line, _, rest = self.pending.partition(b'\n'); self.pending[:] = rest; self.line(bytes(line))
        done = not self.poller.get_map()
        if done:
            status = self.process.poll()
            if status is not None:
                require(not self.pending and status == 0 and
                    self.counts == {'running': 1, 'result': 1, 'marker': 1},
                    'owner_response' if self.owner else 'history_audit')
        return done

    def finish(self, allowed, deadline):
        while not self.pump():
            require(time.monotonic_ns() < deadline, 'phase_deadline'); time.sleep(.01)
        require(not self.pending, 'setup_output')
        status = self.process.wait(timeout=max(.001, (deadline - time.monotonic_ns()) / 1e9))
        require(status == 0 and self.counts == {'running': 1, 'result': 1, 'marker': 1},
                'owner_response' if self.owner else 'history_audit')
        S.namespace_empty_except(allowed)
        self.poller.close(); self.process.stdout.close()
        return self.result


def cgroup_memory_observation():
    """Fixed read-only private-cgroup counters; no raw text or errors escape."""
    result = dict(status='unavailable', oom=None, oom_kill=None, peak_bytes=None)
    def read(path, limit):
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK)
        try:
            require(stat.S_ISREG(os.fstat(fd).st_mode), 'invalid_record')
            raw = os.read(fd, limit + 1)
            require(len(raw) <= limit, 'invalid_record')
            return raw.decode('ascii')
        finally: os.close(fd)
    try:
        rows = read('/sys/fs/cgroup/memory.events', 4096).splitlines()
        values = {}
        for row in rows:
            key, value = row.split()
            require(key not in values and value.isascii() and value.isdecimal() and
                    len(value) <= 19 and int(value) <= (1 << 63) - 1, 'invalid_record')
            values[key] = int(value)
        require('oom' in values and 'oom_kill' in values, 'invalid_record')
        result.update(status='ok', oom=values['oom'], oom_kill=values['oom_kill'])
    except OSError:
        return result
    except Exception:
        result['status'] = 'invalid'; return result
    try:
        peak = read('/sys/fs/cgroup/memory.peak', 64).strip()
        require(peak.isascii() and peak.isdecimal() and len(peak) <= 19 and
                int(peak) <= (1 << 63) - 1, 'invalid_record')
        result['peak_bytes'] = int(peak)
    except Exception:
        pass  # older kernels may lack memory.peak; counters remain independent
    return result


class NativeSession:
    def __init__(self, original, source_backed, reporter):
        self.original, self.reporter, self.observed = original, reporter, source_backed
        self.deadline = min(original, time.monotonic_ns() + D.SESSION_NS)
        self.records, self.owner, self.collector = [], None, ObserverFiles() if source_backed else None
        self.controller = self.weston = self.product = None
        self.input_field = None; self.input_action = 'other'
        self.memory_before = cgroup_memory_observation()
        reporter.runtime_context = self.failure_context
        reporter.stage = 'display'
        S.namespace_empty_except((1,))
        require(not list(EVIDENCE.iterdir()), 'record_file')
        require(not list(WAYLAND.iterdir()), 'display_start')
        self.controller, edge, additions = D.make_channel(original, self.deadline)
        try:
            self.weston = subprocess.Popen(WESTON, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL, close_fds=True, pass_fds=(edge.fileno(),), start_new_session=True,
                env={'PATH': '/usr/bin:/bin', 'HOME': '/nonexistent', 'LANG': 'C.UTF-8',
                     'XDG_RUNTIME_DIR': str(WAYLAND), **additions})
        finally: edge.close()
        self.controller.wait_ready()
        self.require_display_live()
        environment = {'XDG_RUNTIME_DIR': str(WAYLAND), 'WAYLAND_DISPLAY': 'wayland-ui'}
        D.check_product_environment(environment)
        self.product = subprocess.Popen([str(ROOT / ('coordinator-observed' if source_backed else 'coordinator-production'))],
            stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            close_fds=True, pass_fds=(), env=environment, start_new_session=True)
        require(os.getpgid(self.product.pid) == self.product.pid, 'product_status')
        self.controller.bind_process(self.product); self.controller.focus(True)

    def failure_context(self):
        def status(process):
            if process is None: return None
            value = process.poll()
            return value if P.number(value, -64, 255) else None
        records = self.records
        collector_code = None
        if self.collector is not None:
            try: records = self.collector.read(); self.records = records
            except Exception as error:
                code = getattr(error, 'code', None)
                collector_code = code if code in P.CODES else 'internal'
        terminal = []; phase = None
        for record in records:
            P.validate_record(record)
            if record['event'] == 'RoleFinished':
                terminal.append(dict(role=record['role'], exit_status=record['detail']['exit_code']))
            if record['role'] == 'Coordinator' and record['event'] == 'Observation' and record['detail'].get('observation') == 'WidgetSnapshot':
                phase = record['detail']['facts']['phase']
        require(len(terminal) <= 17, 'record_count')
        detail = P.delivery_first_failure(records) if records else None
        return dict(product_status=status(self.product), compositor_status=status(self.weston),
            memory_before=getattr(self, 'memory_before', None), memory_after=cgroup_memory_observation(),
            input_observation=P.input_observation(records),
            field=self.input_field, action=self.input_action, collector_code=collector_code,
            record_count=len(records), phase=phase, terminal_roles=terminal,
            delivery_stage=None if detail is None else detail['stage'],
            delivery_class=None if detail is None else detail['class'],
            controller=None if self.controller is None else self.controller.failure_snapshot())

    def related_delivery_failure(self):
        collector = getattr(self, 'collector', None)
        if collector is not None:
            try:
                # Related closed-schema observation, never an inferred cause.
                self.records = collector.read()
                return P.delivery_first_failure(self.records)
            except Exception:
                pass  # unavailable diagnostics cannot replace the process failure
        return None

    def require_product_live(self):
        status = self.product.poll()
        if status is not None:
            require(P.number(status, -64, 255), 'product_status')
            detail = self.related_delivery_failure()
            self.reporter.note(P.failure(self.reporter.mode, self.reporter.stage,
                'product_status', self.reporter.case,
                product_observation=dict(exit_status=status),
                delivery_stage=None if detail is None else detail['stage'],
                delivery_class=None if detail is None else detail['class']))
            raise S.Rejected('product_status')

    def require_display_live(self):
        if self.weston.poll() is not None:
            observation = self.controller.observe_exited_compositor(self.weston)
            product = getattr(self, 'product', None)
            if product is not None:
                status = product.poll()
                require(status is None or P.number(status, -64, 255), 'product_status')
                observation['product_exit_status'] = status
            detail = self.related_delivery_failure()
            self.reporter.note(P.failure(self.reporter.mode, self.reporter.stage,
                'display_status', self.reporter.case, display_observation=observation,
                delivery_stage=None if detail is None else detail['stage'],
                delivery_class=None if detail is None else detail['class']))
            raise S.Rejected('display_status')

    def check(self):
        require(time.monotonic_ns() < self.original, 'original_deadline')
        require(time.monotonic_ns() < self.deadline, 'phase_deadline')
        self.require_display_live()
        self.require_product_live()
        if self.owner: self.owner.pump()
        if self.collector: self.records = self.collector.read()

    def snapshot(self):
        self.check()
        if len({r['role'] for r in self.records}) != 17: return None
        try: return P.latest_widget_snapshot(self.records, root_pid=self.product.pid)
        except P.Rejected as error:
            if error.code == 'input_widget': return None
            raise

    def wait_snapshot(self, predicate, *, code='input_phase', after=0, allow_revoked=False):
        while True:
            record = self.snapshot()
            if record:
                facts = record['detail']['facts']
                if record['sequence'] > after and predicate(facts): return record
                if facts['phase'] in ('Revoked', 'Finished') and not allow_revoked:
                    raise S.Rejected('source_failure')
            require(time.monotonic_ns() < self.deadline, code); time.sleep(.01)

    @staticmethod
    def widget(record, name, *, enabled=True):
        facts = record['detail']['facts']
        found = [w for w in facts['widgets'] if w['widget'] == name]
        require(len(found) == 1, 'input_widget')
        require(not enabled or found[0]['enabled'], 'input_disabled')
        return found[0]

    def click(self, record, name, *, terminal=False):
        self.check()
        latest = P.latest_widget_snapshot(self.records, root_pid=self.product.pid)
        a, b = record['detail']['facts'], latest['detail']['facts']
        require(a['phase'] == b['phase'] and a['presentation_digest'] == b['presentation_digest'] and
                b['focused'] and self.widget(record, name) == self.widget(latest, name), 'input_phase')
        require(not terminal or (name == 'Close' and b['phase'] == 'Finished'), 'input_phase')
        action = self.controller.terminal_click if terminal else self.controller.click
        return action(*center(b, self.widget(latest, name)))

    def settled_form_snapshot(self):
        """Choose form geometry only after two real stable render intervals.

        Wheel ACK means injection, not the end of native smooth scrolling or
        multiline reflow. Snapshots deduplicate equal geometry, so sequence
        advancement alone cannot establish stability. No input is sent here.
        The existing click revalidation remains the final fail-closed guard.
        """
        record = self.wait_snapshot(lambda s: s['phase'] == 'Selecting' and
                                    s['focused'] and not s['revoked'])
        baseline = record['detail']['facts']['presentation_digest']
        stable = 0
        for _ in range(64):
            self.controller.wait_render_progress()
            latest = self.snapshot()
            require(latest is not None, 'input_phase')
            facts = latest['detail']['facts']
            require(facts['phase'] == 'Selecting' and facts['focused'] and
                    not facts['revoked'] and not facts['raw_blur'] and
                    facts['presentation_digest'] == baseline, 'input_phase')
            # Native frame/pass counters are not layout or semantic state.
            before = {k: v for k, v in record['detail']['facts'].items() if k not in ('frame', 'pass')}
            after = {k: v for k, v in facts.items() if k not in ('frame', 'pass')}
            stable = stable + 1 if before == after else 0
            record = latest
            if stable == 2:
                return record
        raise S.Rejected('input_phase')

    def fill(self, form):
        self.reporter.stage = 'input'
        # Preflight all values and aggregate event ceiling before any field input.
        cost = sum(len(D._ascii_events(form[key])) + 9 for _, key in FIELDS)
        require(cost < D.MAX_COMMANDS - 2048, 'input_budget')
        for name, key in FIELDS:
            self.input_field = name
            for scroll in range(65):
                record = self.settled_form_snapshot()
                matches = [w for w in record['detail']['facts']['widgets'] if w['widget'] == name and w['enabled']]
                if matches:
                    self.input_action = 'select'; self.click(record, name)
                    self.input_action = 'clear'; self.controller.clear_field()
                    self.input_action = 'type'; self.controller.type_ascii(form[key]); break
                require(scroll < 64, 'input_widget')
                visible = [w for w in record['detail']['facts']['widgets'] if w['widget'] in dict(FIELDS)]
                require(visible, 'input_widget')
                target = max(visible, key=lambda w: w['rect']['bottom'])
                self.input_action = 'scroll'
                self.controller.scroll_down(*center(record['detail']['facts'], target))

    def capture(self, record, prior_pixels=None, *, region=None, before_digest=None):
        self.input_action = 'capture'
        self.check()
        read_ns = time.monotonic_ns(); facts = record['detail']['facts']
        if region is None: region = physical_region(facts, self.widget(record, 'Review', enabled=False))
        requested = time.monotonic_ns()
        frame = self.controller.observe()
        try:
            after_digest = pixel_digest(frame.bgra(), region)
            if before_digest is None: before_digest = pixel_digest(prior_pixels, region)
            latest = self.snapshot()
            require(latest is not None, 'source_paint')
            current = latest['detail']['facts']
            require(current['phase'] == facts['phase'] and current['presentation_digest'] == facts['presentation_digest'] and
                    current['focused'] == facts['focused'] and current['revoked'] == facts['revoked'], 'source_paint')
            if 'Review' in {w['widget'] for w in facts['widgets']}:
                require(self.widget(latest, 'Review', enabled=False) == self.widget(record, 'Review', enabled=False), 'source_paint')
            result = dict(snapshot_sequence=record['sequence'], frame=facts['frame'], **{'pass': facts['pass']},
                presentation_digest=facts['presentation_digest'], snapshot_read_ns=read_ns,
                requested_ns=requested, completed_ns=time.monotonic_ns(), request_receipt=dataclasses.asdict(frame.barrier),
                observed_receipt=dataclasses.asdict(frame.receipt), region=region,
                region_before_digest=before_digest, region_after_digest=after_digest)
            require(before_digest != after_digest, 'source_paint')
            return result
        finally: frame.wipe()

    def drain_product(self):
        self.reporter.stage = 'drain'
        status = self.product.wait(timeout=max(.001, (self.deadline - time.monotonic_ns()) / 1e9))
        require(status == 0, 'product_status')
        # Includes adopted live children AND zombies. No rescue/reap substitutes
        # for the fixed product owners' actual natural cleanup.
        S.namespace_empty_except((1, self.weston.pid))
        observed = time.monotonic_ns()
        require(observed < self.original, 'original_deadline')
        return dict(root_pid=self.product.pid, exit_status=status, remaining_pids=[],
                    remaining_process_groups=[], observed_ns=observed)

    def end_display(self):
        # Product must already be independently exited/reaped and namespace empty.
        require(self.product.returncode == 0, 'product_status')
        S.namespace_empty_except((1, self.weston.pid))
        cleanup_deadline = min(self.original, time.monotonic_ns() + 5_000_000_000)
        if self.weston.poll() is None: self.weston.terminate()
        remaining = cleanup_deadline - time.monotonic_ns()
        require(remaining > 0, 'cleanup_failed')
        status = self.weston.wait(timeout=remaining / 1e9)
        self.controller.finish_after_product(status, cleanup_deadline)
        S.namespace_empty_except((1,))
        # Only stale private compositor socket/lock, never source custody.
        for path in WAYLAND.iterdir():
            require(path.name in ('wayland-ui', 'wayland-ui.lock'), 'display_status')
            meta = path.stat(follow_symlinks=False)
            require(meta.st_uid == S.UID and meta.st_gid == S.UID and
                    (stat.S_ISSOCK(meta.st_mode) or stat.S_ISREG(meta.st_mode)), 'display_status')
            path.unlink()


def source_case(case, original, handoff_raw, original_metadata, artifact_digest, reporter):
    reporter.case = case
    session = NativeSession(original, True, reporter)
    baseline = None
    try:
        handoff, current = original_facts(S.read_private(S.BASE / 'handoff.json', S.MAX_HANDOFF), original)
        require(current == original_metadata, 'original_request')
        session.fill(handoff['fixture']['form'])
        prepare = session.wait_snapshot(lambda s: s['phase'] == 'Selecting' and s['focused'] and
            any(w['widget'] == 'Prepare' and w['enabled'] for w in s['widgets']))
        session.input_action = 'capture'
        with session.controller.observe() as frame: baseline = bytearray(frame.bgra())
        reporter.stage = 'prepare'; session.input_field = None; session.input_action = 'prepare'; session.click(prepare, 'Prepare')
        source = session.wait_snapshot(lambda s: s['phase'] == 'Reading' and s['focused'] and
            not s['revoked'] and s['presentation_digest'] is not None, code='source_prepare', after=prepare['sequence'])
        source_paint = session.capture(source, baseline); D._wipe(baseline); baseline = None
        action = focus_out = refocus = None
        if case == 'cancel':
            reporter.stage = 'cancel'; action = session.click(source, 'Cancel')
        elif case == 'blur':
            reporter.stage = 'blur'; action = focus_out = session.controller.focus(False)
            session.wait_snapshot(lambda s: s['revoked'] and not s['focused'] and s['presentation_digest'] is None,
                                  after=source['sequence'], allow_revoked=True)
            refocus = session.controller.focus(True)
        else:
            reporter.stage = 'append'
            for scroll in range(129):
                record = session.wait_snapshot(lambda s: s['phase'] == 'Reading' and s['focused'] and not s['revoked'])
                if any(w['widget'] == 'Continue' and w['enabled'] for w in record['detail']['facts']['widgets']): break
                require(scroll < 128, 'input_widget')
                session.controller.scroll_down(*center(record['detail']['facts'], session.widget(record, 'Review', enabled=False)))
                time.sleep(.03)  # fixed real wheel; unchanged clipped geometry need not emit a snapshot
            session.click(record, 'Continue')
            ack = session.wait_snapshot(lambda s: s['phase'] == 'Acknowledging' and s['focused'], after=record['sequence'])
            session.click(ack, 'Acknowledge')
            armed = session.wait_snapshot(lambda s: s['phase'] == 'Acknowledging' and s['acknowledged'] and
                any(w['widget'] == 'Arm' and w['enabled'] for w in s['widgets']), after=ack['sequence'])
            action = session.click(armed, 'Arm')
            while True:
                session.check()
                native = [r for r in session.records if r['role'] == 'Coordinator' and r['event'] == 'Arm' and r['detail']['direction'] == 'Native']
                if native: require(len(native) == 1, 'native_arm'); break
                time.sleep(.01)
            session.owner = LibSelector(OWNER_SELECTOR, original, reporter, owner=True)
        cleared = session.wait_snapshot(lambda s: s['phase'] == 'Finished' and s['focused'] and s['revoked'] and
            s['presentation_digest'] is None, code='source_clear', after=source['sequence'], allow_revoked=True)
        cleared_paint = session.capture(cleared, region=source_paint['region'], before_digest=source_paint['region_after_digest'])
        if session.owner:
            owner = session.owner.finish((1, session.weston.pid, session.product.pid), session.deadline)
        else: owner = None
        session.click(cleared, 'Close', terminal=True)
        drain = session.drain_product(); records = session.collector.read(final=True)
        P.validate_trace(records, root_pid=session.product.pid, root_status=0)
        session.end_display()
        reporter.stage = 'audit'
        selector = S.SELECTOR_PREFIX + ('coordinator_originals_after_one_exact_append' if case == 'append'
            else 'coordinator_pristine_originals_after_cancel_or_blur')
        audit = LibSelector(selector, original, reporter).finish((1,), original)
        _, current = original_facts(S.read_private(S.BASE / 'handoff.json', S.MAX_HANDOFF), original)
        facts = dict(result=audit, original=original_metadata, current=current, drain=drain, audited_ns=time.monotonic_ns())
        paint = dict(root_pid=session.product.pid, app_id=D.APP_ID, artifact_digest=artifact_digest,
            original_artifact_digest=artifact_digest, source=source_paint, cleared=cleared_paint,
            action=dataclasses.asdict(action), focus_out=None if focus_out is None else dataclasses.asdict(focus_out),
            refocus=None if refocus is None else dataclasses.asdict(refocus))
        result = P.project_case(records, case, root_pid=session.product.pid, root_status=0,
            audit=facts, paint=paint, owner_client=owner)
        session.collector.erase_after_case()
        return result
    except BaseException as error:
        reporter.error(error, session.records)
        raise
    finally:
        if baseline is not None: D._wipe(baseline)
        # On any failure PID1 returns error; the outer owns whole-container kill,
        # removal and disappearance verification. Never turn forced cleanup into pass.
        if session.controller: session.controller.close()


def smoke_case(original, reporter):
    reporter.case = 'smoke'; session = NativeSession(original, False, reporter)
    try:
        with session.controller.observe(): pass
        session.controller.close_window()
        session.drain_product(); session.end_display()
        return dict(name='smoke', product_exit=0, surface_bound=True, frame_observed=True, natural_tree_drain=True)
    except BaseException as error:
        reporter.error(error); raise
    finally:
        if session.controller: session.controller.close()


def reviewed_runtime_main(mode):
    """Closed smoke or single-fixture route, only inside the owned CI image."""
    reporter = FirstRuntimeFailure(mode); cases = []; setup_ms = None; timing = {}
    try:
        require(mode in P.MODES, 'invalid_record')
        original, started, custody = prepare_runtime(mode == 'fixture', reporter.note, timing)
        setup_ms = (time.monotonic_ns() - started) // 1_000_000
        if mode == 'fixture':
            reporter.stage = 'custody'
            metadata, fds = S.private_handoff(original)
            try: require(metadata == custody, 'custody_identity')
            finally:
                for fd in fds: os.close(fd)
            raw = S.read_private(S.BASE / 'handoff.json', S.MAX_HANDOFF)
            _, retained = original_facts(raw, original)
            with (ROOT / 'coordinator-observed').open('rb') as image:
                digest = hashlib.file_digest(image, 'sha256').hexdigest()
            for case in P.CASES:
                cases.append(source_case(case, original, raw, retained, digest, reporter))
        else: cases.append(smoke_case(original, reporter))
        S.namespace_empty_except((1,)); require(time.monotonic_ns() < original, 'original_deadline')
        result = dict(schema_version=1, mode=mode, outcome='passed', first_failure=None,
                      setup_elapsed_ms=setup_ms, cases=cases, natural_empty=True)
        P.validate_runtime_result(result, mode)
        print(json.dumps(result, separators=(',', ':')), flush=True)
        return 0
    except BaseException as error:
        reporter.error(error)
        if setup_ms is None and 'started' in timing:
            setup_ms = (time.monotonic_ns() - timing['started']) // 1_000_000
        result = dict(schema_version=1, mode=mode, outcome='error', first_failure=reporter.value,
                      setup_elapsed_ms=setup_ms, cases=cases, natural_empty=False)
        P.validate_runtime_result(result, mode)
        print(json.dumps(result, separators=(',', ':')), flush=True)
        return 1


def invalid_invocation():
    mode = sys.argv[1] if len(sys.argv) == 2 and sys.argv[1] in P.MODES else 'fixture'
    first = P.failure(mode, 'lifecycle', 'invalid_record')
    print('CI_UI_FAILURE ' + json.dumps(first, separators=(',', ':')), flush=True)
    value = dict(schema_version=1, mode=mode, outcome='error', first_failure=first,
                 setup_elapsed_ms=None, cases=[], natural_empty=False)
    P.validate_runtime_result(value, mode)
    print(json.dumps(value, separators=(',', ':')), flush=True)
    return 1


if __name__ == '__main__':
    sys.exit(reviewed_runtime_main(sys.argv[1]) if len(sys.argv) == 2 and sys.argv[1] in P.MODES
             else invalid_invocation())
