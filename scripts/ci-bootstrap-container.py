#!/usr/bin/env python3
"""CI-only PID1. Nonsecret pin setup, ordinary-UID exec, and bounded adoption.

This file is never imported by the product. It is copied into a disposable,
networkless container; the fixed pin exists solely in that container's tmpfs.
"""
import hashlib
import importlib.util
import json
import os
import pathlib
import resource
import stat
import subprocess
import sys
import time

ROOT = pathlib.Path('/opt/bootstrap')
SPEC = importlib.util.spec_from_file_location('bootstrap_projection', ROOT / 'ci-bootstrap-output.py')
P = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(P)
UID = 10001
CAP_SETUP = (1 << 6) | (1 << 7)  # SETGID and SETUID, setup only; never effective in product.


def require(ok, code):
    if not ok:
        raise P.Rejected(code)


def identity():
    fields = {}
    for line in pathlib.Path('/proc/self/status').read_text().splitlines():
        name, _, value = line.partition(':')
        fields[name] = value.strip()
    require(os.getresuid() == (UID, UID, UID) and os.getresgid() == (UID, UID, UID)
            and os.getgroups() == []
            and fields['Uid'].split() == [str(UID)] * 4
            and fields['Gid'].split() == [str(UID)] * 4, 'identity')
    require(all(int(fields[name], 16) == 0 for name in ('CapInh', 'CapPrm', 'CapEff', 'CapAmb')),
            'capabilities')
    # Bounding bits alone confer no permission. Both are unusable after setresuid
    # clears permitted/effective sets and Docker's NNP blocks exec elevation.
    require(int(fields['CapBnd'], 16) == CAP_SETUP and fields['NoNewPrivs'] == '1', 'capabilities')


def prepare(case):
    require(os.getpid() == 1 and os.getuid() == 0 and os.geteuid() == 0, 'container_context')
    require(len(list(pathlib.Path('/proc/self/task').iterdir())) == 1, 'single_thread')
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    os.umask(0o077)
    os.environ.clear()
    manifest = P.loads((ROOT / 'manifest.json').read_bytes())
    require(set(manifest) == {'schema_version', 'source', 'images'} and manifest['schema_version'] == 1,
            'manifest')
    require(P.SHA.fullmatch(manifest['source']) is not None and set(manifest['images']) == set(P.CASES), 'manifest')
    for directory in (pathlib.Path('/'), pathlib.Path('/opt'), ROOT, ROOT / 'images'):
        directory_meta = directory.stat(follow_symlinks=False)
        require(stat.S_ISDIR(directory_meta.st_mode) and directory_meta.st_uid == 0
                and stat.S_IMODE(directory_meta.st_mode) & 0o022 == 0
                and stat.S_IMODE(directory_meta.st_mode) & 0o005 == 0o005, 'image')
    exe = ROOT / 'images' / case
    meta = exe.stat(follow_symlinks=False)
    require(stat.S_ISREG(meta.st_mode) and meta.st_uid == 0 and meta.st_mode & 0o022 == 0
            and meta.st_mode & 0o111 and 0 < meta.st_size <= 512 * 1024 * 1024, 'image')
    with exe.open('rb') as stream:
        digest = hashlib.file_digest(stream, 'sha256').hexdigest()
    require(digest == manifest['images'][case], 'image')
    pin_dir = pathlib.Path('/etc/wholepact')
    meta_dir = pin_dir.stat(follow_symlinks=False)
    require(stat.S_ISDIR(meta_dir.st_mode) and meta_dir.st_uid == 0 and meta_dir.st_mode & 0o022 == 0, 'pin')
    pin = dict(schema_version=1, profile='financial-coordinator-common-image-linux-v1',
               executable_device=meta.st_dev, executable_inode=meta.st_ino,
               executable_size=meta.st_size, executable_sha256=digest)
    path = pin_dir / 'financial-coordinator-common-image-v1.json'
    with path.open('xb') as stream:
        stream.write(json.dumps(pin, separators=(',', ':'), sort_keys=True).encode('ascii'))
    path.chmod(0o444)
    require(path.stat().st_uid == 0, 'pin')
    evidence = pathlib.Path('/ci-evidence').stat(follow_symlinks=False)
    require(stat.S_ISDIR(evidence.st_mode) and evidence.st_uid == UID and evidence.st_gid == UID
            and stat.S_IMODE(evidence.st_mode) == 0o700, 'evidence_setup')
    os.setgroups([])
    os.setresgid(UID, UID, UID)
    os.setresuid(UID, UID, UID)
    identity()
    require(len(list(pathlib.Path('/proc/self/task').iterdir())) == 1, 'single_thread')
    return exe


def drain(deadline):
    """PID1 adoption is observed separately, never substituted for owned reaps."""
    adopted = []
    while time.monotonic() < deadline:
        try:
            pid, status = os.waitpid(-1, os.WNOHANG)
        except ChildProcessError:
            return adopted, True
        if pid:
            adopted.append((pid, status))
            require(len(adopted) <= 32, 'descendant_bound')
        else:
            time.sleep(0.01)
    return adopted, False


def evidence():
    directory = pathlib.Path('/ci-evidence')
    names = list(directory.iterdir())
    require(len(names) <= 32, 'evidence_limit')
    rows = []
    total = 0
    for path in names:
        require(P.PID_FILE.fullmatch(path.name) is not None, 'evidence_file')
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
        with os.fdopen(fd, 'rb') as stream:
            meta = os.fstat(stream.fileno())
            require(stat.S_ISREG(meta.st_mode) and meta.st_uid == UID and meta.st_nlink == 1
                    and 0 < meta.st_size <= 65536, 'evidence_file')
            raw = stream.read(65537)
        total += len(raw)
        require(len(raw) == meta.st_size and total <= 512 * 1024 and raw.endswith(b'\n'), 'evidence_limit')
        for line in raw.splitlines():
            require(0 < len(line) <= 8192, 'evidence_limit')
            row = P.loads(line)
            require(type(row) is dict and row.get('pid') == int(path.stem), 'evidence_file')
            rows.append(row)
            require(len(rows) <= 256, 'evidence_limit')
    return rows


def main():
    case = sys.argv[1] if len(sys.argv) == 2 and sys.argv[1] in P.CASES else 'production'
    result = P.result(case, 'error', 'setup', 'arguments')
    child = None
    observed_counts = {}
    started = time.monotonic()
    try:
        require(len(sys.argv) == 2 and sys.argv[1] in P.CASES, 'arguments')
        exe = prepare(case)
        # Genuine exec into the exact pinned image; no preexec_fn, role selectors,
        # inherited observation FD, ambient environment, or Rust test harness.
        child = subprocess.Popen([str(exe)], stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                                 stderr=subprocess.DEVNULL, env={}, close_fds=True)
        result = P.result(case, 'error', 'runtime', 'runtime_deadline')
        try:
            status = child.wait(timeout=45)
        except subprocess.TimeoutExpired:
            # No direct-process-only cleanup claim. Returning PID1 ends this PID
            # namespace, and host supervisor also independently kills/removes it.
            return result
        adopted, empty = drain(time.monotonic() + 5)
        result = P.result(case, 'error', 'cleanup', 'descendants_remain')
        result['adopted_reaped'] = len(adopted)
        if not empty:
            return result
        rows = evidence()
        observed_counts = P.observed_counts(rows, case, adopted)
        result = P.validate_case(case, rows, status, adopted, child.pid)
        result['natural_empty'] = True
        return result
    except P.Rejected as error:
        # Preserve the first finite failure. No exception text, path or PID is
        # projected; any later cleanup uncertainty remains a separate boolean.
        result = P.result(case, 'error', 'evidence' if child is not None else 'setup', error.code)
        result.update(observed_counts)
        return result
    except Exception:
        result = P.result(case, 'error', 'evidence' if child is not None else 'setup', 'internal')
        result.update(observed_counts)
        return result
    finally:
        elapsed = min(60000, max(0, int((time.monotonic() - started) * 1000)))
        result['elapsed_ms'] = elapsed


if __name__ == '__main__':
    outcome = main()
    print(json.dumps(outcome, sort_keys=True, separators=(',', ':')), flush=True)
    sys.exit(0 if outcome['outcome'] == 'passed' else 1)
