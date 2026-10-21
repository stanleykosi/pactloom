#!/usr/bin/env python3
"""Disposable UI CI PID1, new recovery revision. Import performs no setup.

Only SETUID/GID exist during fixture custody. Root does not read credential
bytes, although SETUID technically permits impersonation. All product/display
work must follow the verified permanent UID drop. Main stays fail-closed until
reviewed genuine input, independent evidence/audit, and cleanup are joined.
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


def image_manifest():
    require(ROOT == pathlib.Path('/opt/ci-ui'), 'image_directory')
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
            require(stat.S_ISREG(meta.st_mode) and meta.st_uid == 0 and meta.st_gid == 0 and
                    meta.st_nlink == 1 and meta.st_size == pin['size'] and
                    stat.S_IMODE(meta.st_mode) == (0o555 if name in ARTIFACTS else 0o444), 'image_file')
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
                source_boundary=value['source_boundary'], source_outcome=value['source_outcome']))
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


def prepare_runtime(source_backed, report_failure):
    root_context(); manifest = image_manifest(); fixture_tmpfs()
    base = base_passwd(); write_passwd(base, '/nonexistent', final=False)
    started = time.monotonic_ns(); original = started + 900_000_000_000
    custody = None
    if source_backed:
        custody = setup_one_fixture(original, started, report_failure)
        write_passwd(base, custody['home_path'], final=True)
    create_pin('coordinator-observed' if source_backed else 'coordinator-production', manifest)
    S.namespace_empty_except((1,))
    os.setgroups([]); os.setresgid(S.UID, S.UID, S.UID); os.setresuid(S.UID, S.UID, S.UID)
    S.identity()
    return original, started, custody


def disabled_main():
    mode = sys.argv[1] if len(sys.argv) == 2 and sys.argv[1] in P.MODES else 'fixture'
    first = P.failure(mode, 'lifecycle', 'integration_not_frozen')
    print('CI_UI_FAILURE ' + json.dumps(first, separators=(',', ':')), flush=True)
    value = dict(schema_version=1, mode=mode, outcome='error', first_failure=first,
                 setup_elapsed_ms=None, cases=[], natural_empty=False)
    P.validate_runtime_result(value, mode)
    print(json.dumps(value, separators=(',', ':')), flush=True)
    return 1


if __name__ == '__main__':
    sys.exit(disabled_main())
