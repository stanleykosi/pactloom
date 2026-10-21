#!/usr/bin/env python3
"""Explicit-pinned CI binary reuse; null pin keeps the original fresh path.

No runtime credentials, authority or fixture state is reused. GitHub provenance
and both archive hashes are checked before inspecting/restoring binary bytes.
This wrapper changes only the CI compilation step, never product approval.
"""
import hashlib
import importlib.util
import json
import os
import pathlib
import shutil
import signal
import stat
import struct
import sys
import tarfile
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request
import zipfile

HERE = pathlib.Path(__file__).resolve().parent

def load(name, file):
    spec = importlib.util.spec_from_file_location(name, HERE / file)
    module = importlib.util.module_from_spec(spec); sys.modules[name] = module
    spec.loader.exec_module(module)
    return module

S = load('reuse_supervisor', 'ci-ui-supervisor.py')
R = load('reuse_provenance', 'ci-ui-reuse.py')
A = S.A
PIN = HERE / 'ci-ui-reuse-pin.json'
API = 'https://api.github.com/repos/stanleykosi/pactloom/'

class Rejected(Exception):
    pass

def need(ok, code):
    if not ok:
        raise Rejected(code)

class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def api(path, token, *, redirect=False):
    need(type(path) is str and path and not path.startswith('/') and '..' not in path and
         all(c.isalnum() or c in '/?=&-_' for c in path), 'api_path')
    headers = {'Accept': 'application/vnd.github+json', 'X-GitHub-Api-Version': '2022-11-28'}
    if token:
        headers['Authorization'] = 'Bearer ' + token
    opener = urllib.request.build_opener(NoRedirect())
    try:
        response = opener.open(urllib.request.Request(API + path, headers=headers), timeout=20)
    except urllib.error.HTTPError as error:
        if redirect and error.code == 302:
            location = error.headers.get('Location', '')
            error.close()
            return storage_url(location)
        raise Rejected('api_response') from None
    with response:
        need(not redirect and response.status == 200 and response.geturl() == API + path, 'api_response')
        raw, deadline = bytearray(), time.monotonic() + 60
        while True:
            need(time.monotonic() < deadline, 'api_deadline')
            chunk = response.read1(65536)
            if not chunk:
                break
            raw.extend(chunk); need(len(raw) <= 4 * 1024 * 1024, 'api_limit')
        return json.loads(raw, object_pairs_hook=A.pairs,
            parse_constant=lambda _: (_ for _ in ()).throw(Rejected('api_json')))


def storage_url(value):
    url = urllib.parse.urlsplit(value)
    host = url.hostname or ''
    need(url.scheme == 'https' and not url.username and not url.password and
         url.port in (None, 443) and not url.fragment and
         (host.endswith('.blob.core.windows.net') or host.endswith('.actions.githubusercontent.com')),
         'storage_origin')
    return value


def download_archive(url, destination, expected_sha):
    # Never forward the API Authorization header to the signed storage URL.
    opener = urllib.request.build_opener(NoRedirect())
    deadline, total, digest = time.monotonic() + 300, 0, hashlib.sha256()
    with opener.open(urllib.request.Request(storage_url(url)), timeout=20) as response:
        need(response.status == 200 and response.geturl() == url, 'download_response')
        with pathlib.Path(destination).open('xb') as stream:
            while True:
                need(time.monotonic() < deadline, 'download_deadline')
                chunk = response.read1(1024 * 1024)
                if not chunk:
                    break
                total += len(chunk); need(total <= R.MAX_ARCHIVE, 'download_limit')
                stream.write(chunk); digest.update(chunk)
    need(total > 0 and digest.hexdigest() == expected_sha, 'archive_digest')


def unpack_single_bundle(archive, destination, expected_sha):
    # Bound the central directory BEFORE ZipFile parses it. One ordinary ZIP
    # member only; no Zip64, comments, links, arbitrary extraction or huge lists.
    with pathlib.Path(archive).open('rb') as stream:
        stream.seek(0, 2); size = stream.tell(); need(size >= 22, 'zip_header')
        stream.seek(-22, 2); end = stream.read(22)
    signature, disk, cd_disk, disk_count, count, cd_size, cd_offset, comment = struct.unpack('<4s4H2IH', end)
    need(signature == b'PK\x05\x06' and disk == cd_disk == comment == 0 and
         disk_count == count == 1 and 0 < cd_size <= 4096 and cd_offset + cd_size == size - 22,
         'zip_directory')
    with zipfile.ZipFile(archive) as zipped:
        entries = zipped.infolist(); need(len(entries) == 1, 'zip_set')
        item = entries[0]
        mode = item.external_attr >> 16
        need(item.filename == 'build.tar' and not item.is_dir() and not item.flag_bits & 1 and
             (mode == 0 or stat.S_ISREG(mode)) and
             0 < item.file_size <= A.MAX_TOTAL + A.MAX_MANIFEST + 65536, 'zip_entry')
        total, digest = 0, hashlib.sha256()
        with zipped.open(item) as source, pathlib.Path(destination).open('xb') as output:
            while chunk := source.read(1024 * 1024):
                total += len(chunk); need(total <= item.file_size, 'bundle_limit')
                output.write(chunk); digest.update(chunk)
        need(total == item.file_size and digest.hexdigest() == expected_sha, 'bundle_digest')
    pathlib.Path(destination).chmod(0o444)


def source_inventory():
    inventory = {}
    rows = S.checked(['git', 'ls-tree', '-rz', '--full-tree', 'HEAD'], 'source', limit=16 * 1024 * 1024)
    for row in rows.split(b'\0'):
        if not row:
            continue
        fields, path = row.split(b'\t', 1); mode, kind, _ = fields.split(b' ')
        need(mode in (b'100644', b'100755') and kind == b'blob', 'source_entry')
        name = path.decode('ascii')
        need(name not in inventory and not name.startswith('/') and
             all(p not in ('', '.', '..') for p in name.split('/')), 'source_path')
        file = S.REPO / name; meta = file.lstat()
        need(stat.S_ISREG(meta.st_mode) and meta.st_nlink == 1 and meta.st_size <= 64 * 1024 * 1024,
             'source_file')
        digest = hashlib.sha256(mode + b'\0')
        with file.open('rb') as stream:
            while chunk := stream.read(1024 * 1024): digest.update(chunk)
        inventory[name] = digest.hexdigest()
    return inventory


def manifest_and_restore(bundle, producer, current, destination):
    # The downloaded tar SHA was independently pinned/verified first. Reading
    # its bounded manifest is still shape validation, not provenance proof.
    with pathlib.Path(bundle).open('rb') as stream:
        member = tarfile.TarInfo.frombuf(stream.read(512), 'ascii', 'strict')
        need(member.name == 'manifest.json' and member.type == tarfile.REGTYPE and
             0 < member.size <= A.MAX_MANIFEST, 'manifest')
        value = json.loads(stream.read(member.size), object_pairs_hook=A.pairs)
    A.validate_manifest(value, producer, value.get('closure'))
    changed = R.validate_closure(value['closure'], current)
    A.verify_bundle(bundle, producer, value['closure'])
    destination = pathlib.Path(destination); destination.mkdir(mode=0o700, exist_ok=False)
    # Verified fixed ordinary tar only; write known names exclusively, never
    # use extract/extractall, restore metadata, or execute these files here.
    with tarfile.open(bundle, 'r:') as archive:
        for name in A.NAMES:
            with archive.extractfile(name) as source, (destination / name).open('xb') as target:
                shutil.copyfileobj(source, target, 1024 * 1024)
            (destination / name).chmod(0o555)
            need(A.file_pin(destination / name) == value['files'][name], 'restored_digest')
    return value['files'], changed


def run():
    # Remove token from the environment before ANY git/build/product subprocess.
    token = os.environ.pop('UI_ARTIFACT_READ_TOKEN', '')
    sha, _ = S.context(); S.exact_source(sha)
    raw = PIN.read_bytes(); need(len(raw) <= 4096, 'pin_limit')
    pin = json.loads(raw, object_pairs_hook=A.pairs)
    sys.argv = ['ci-ui-supervisor.py', 'run']
    if pin is None:
        return S.main()
    R.validate_pin(pin)
    work = pathlib.Path(tempfile.mkdtemp(prefix='ui-reuse-', dir=os.environ['RUNNER_TEMP']))
    try:
        run_info = api(f"actions/runs/{pin['run_id']}/attempts/{pin['attempt']}", token)
        job = api(f"actions/jobs/{pin['job_id']}", token)
        artifact = api(f"actions/artifacts/{pin['artifact_id']}", token)
        commit = api('git/commits/' + pin['source'], token)
        need(type(commit) is dict and commit.get('sha') == pin['source'] and
             type(commit.get('tree')) is dict, 'commit')
        producer = R.validate_provenance(pin, run_info, job, artifact, commit['tree'].get('sha'))
        url = api(f"actions/artifacts/{pin['artifact_id']}/zip", token, redirect=True)
        download_archive(url, work / 'archive.zip', pin['archive_sha256'])
        unpack_single_bundle(work / 'archive.zip', work / 'build.tar', pin['bundle_sha256'])
        inventory = source_inventory()
        files, changed = manifest_and_restore(work / 'build.tar', producer, inventory, work / 'verified')
        S.exact_source(sha)
        restored = False
        original_emit = S.emit
        def report(kind, value):
            if kind == 'RESULT':
                value = dict(value, build_provenance=dict(requested_reuse=True,
                    artifacts_restored=restored, freshly_compiled=False,
                    producer=producer, artifact_id=pin['artifact_id']))
            original_emit(kind, value)
        S.emit = report
        def restore(_root, current_sha, context, foundation):
            nonlocal restored
            need(current_sha == sha and source_inventory() == inventory, 'source_changed')
            target = context / 'artifacts'; target.mkdir()
            pins = dict(foundation)
            for name in A.NAMES:
                shutil.copyfile(work / 'verified' / name, target / name)
                (target / name).chmod(0o555)
                need(A.file_pin(target / name) == files[name], 'restored_digest')
                pins[name] = files[name]
            lock = S.I.validate_manifest((HERE / 'ci-ui-packages.json').read_bytes())
            S.write_context_files(context, S.I.render_build_files(lock, pins))
            restored = True
            S.emit('BUILD_REUSE', dict(producer=producer, artifact_id=pin['artifact_id'],
                source=sha, changed_runtime_paths=changed, freshly_compiled=False,
                archive_sha256=pin['archive_sha256'], bundle_sha256=pin['bundle_sha256']))
        S.build_inputs = restore
        # Never re-export old binaries as a freshly compiled current producer.
        S.export_compiled_artifacts = lambda *_: None
        return S.main()
    finally:
        shutil.rmtree(work)

ERROR_CODES = frozenset('''api_path api_response api_limit api_deadline api_json storage_origin
download_response download_deadline download_limit archive_digest zip_header
zip_directory zip_set zip_entry bundle_limit bundle_digest source_entry
source_path source_file manifest commit source_changed restored_digest pin_limit
pin source identity digest records tree run repository job steps upload artifact
artifact_origin closure closure_entry compile_inputs_changed compile_inputs_missing
manifest_size canonical provenance closure_mismatch recipe file_set file_pin
total_size bundle_file archive_header archive_entry archive_pin archive_truncated
archive_padding archive_tail elf duplicate_key json version'''.split())

if __name__ == '__main__':
    def interrupted(_signum, _frame):
        raise S.Failure('supervisor', 'interrupted')
    signal.signal(signal.SIGTERM, interrupted)
    signal.signal(signal.SIGINT, interrupted)
    try:
        sys.exit(run())
    except Exception as error:
        # No URL, token, arbitrary response, private path or raw runtime output.
        code = error.args[0] if isinstance(error, (Rejected, R.Rejected, A.Rejected)) and error.args else None
        code = code if type(code) is str and code in ERROR_CODES else 'internal'
        print('CI_UI_REUSE_FAILURE ' + json.dumps({'code': code}, separators=(',', ':')), flush=True)
        sys.exit(1)
