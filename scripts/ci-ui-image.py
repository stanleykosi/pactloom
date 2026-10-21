"""Source-only helpers for the separately gated, disposable UI CI image.

Importing this module does nothing. There is deliberately no command-line entry
point. Only the parent supervisor, after its isolated-CI authorization/context
checks and source review, may call the staging functions. Never use them to
prepare or install packages on a user's computer. The pure functions and tests
do not establish package installation, module ABI, or rendered UI behavior.

The reviewed lock is a byte-pinned, signed-Debian-metadata-derived closure, not
an instruction to resolve today's repository. No extra dependency, alternate
origin, newer/older base version, or optional recommendation is accepted.
"""
import hashlib
import io
import json
import lzma
import math
import os
import pathlib
import re
import selectors
import stat
import subprocess
import tarfile
import time

LOCK_SHA256 = '2c86592b3b931cb88024205be851caafaa2845f4620d6a950d43d760d94e8127'
CANONICAL_SHA256 = 'f9dbd0aed8b89fe7000a8be3d31d25e6ca67560eee84b6f8e8013585b35eb6fb'
BASE_IMAGE = 'docker.io/library/python@sha256:8fb4cfa1a2616d7b8e0c2175cc6ad68f5729c34ea8488c0b360d2934b7be9024'
ARCHIVE_ORIGIN = 'https://deb.debian.org/debian/'
# Official Debian source .dsc: weston_14.0.2-1.dsc, SHA256
# 7c06118894b6274212f68e61c138a87ccbb869a5d3835aaa543570c004f8ec65.
# Its Checksums-Sha256 stanza supplies the exact archive name/size/digest.
SOURCE_URL = ARCHIVE_ORIGIN + 'pool/main/w/weston/weston_14.0.2.orig.tar.xz'
SOURCE_BYTES = 2043392
SOURCE_SHA256 = 'b47216b3530da76d02a3a1acbf1846a9cd41d24caa86448f9c46f78f20b6e0ac'
PRIVATE_HEADERS = {
    'libweston/backend.h': (10776, '034da84d7a8689c0829f311e47da87603784a05f26a7981133372392028ada86'),
    'libweston/libweston-internal.h': (19488, 'dbffca62b71a3de39c96d4de1d8371afd07949408b418c0f9aff26eb44f6a1e3'),
    'libweston/pixel-formats.h': (13759, '1ce20266504f88a7a59ab3605c8d0ed2afeeb308d93ae370eb9d4953f679f0df'),
    'libweston/color.h': (20611, '874f926591e85fa9677c1f461728f747e2f29ce27a4dd73a2cefe5cfb57121dd'),
    'libweston/backend-drm/drm-kms-enums.h': (4733, '0462bb5d8cd93561119f0f660891a6d6ea9d9179a202d90b7d12ed69d2453f70'),
}
RUNTIME_FILES = ('ci-ui-container.py', 'ci-ui-setup-wrapper.py',
                 'ci-ui-controller.py', 'ci-ui-output.py')
ARTIFACT_FILES = ('coordinator-production', 'coordinator-observed', 'pristine-setup')
MODULE_SOURCE = 'ci-ui-weston-module.c'
MODULE_BINARY = 'ci-ui-weston-module.so'
ROOT = '/opt/ci-ui'
MAX_LOCK_BYTES = 512 * 1024
MAX_STAGE_SECONDS = 900
MAX_DOWNLOAD_SECONDS = 90
MAX_TAR_BYTES = 64 * 1024 * 1024
MAX_TAR_ENTRIES = 8192
UNION_PACKAGE_COUNT = 258
UNION_DOWNLOAD_BYTES = 207036460
NAME = re.compile(r'[a-z0-9][a-z0-9+.-]*\Z')
VERSION = re.compile(r'[0-9][A-Za-z0-9.+:~\-]*\Z')
SHA = re.compile(r'[0-9a-f]{64}\Z')
DEP = re.compile(r'([a-z0-9][a-z0-9+.-]*)(?::(?:any|native))?(?:\s+\((<<|<=|=|>=|>>) ([0-9][A-Za-z0-9.+:~\-]*)\))?\Z')


class Rejected(ValueError):
    """Finite error only; never expose fetched bytes or subprocess output."""
    def __init__(self, code, *, cleanup_failed=False):
        self.code = code
        self.cleanup_failed = cleanup_failed
        super().__init__(code)


def _require(condition, code):
    if not condition:
        raise Rejected(code)


def _unique(pairs):
    result = {}
    for key, value in pairs:
        _require(key not in result, 'duplicate_key')
        result[key] = value
    return result


def _canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=True).encode('ascii')


def _reviewed(manifest):
    _require(type(manifest) is dict, 'manifest')
    try:
        digest = hashlib.sha256(_canonical(manifest)).hexdigest()
    except (TypeError, ValueError):
        raise Rejected('manifest') from None
    _require(digest == CANONICAL_SHA256, 'manifest_pin')


def validate_manifest(raw):
    """Accept only the exact reviewed lock bytes, then independently audit closure."""
    _require(type(raw) is bytes and 0 < len(raw) <= MAX_LOCK_BYTES, 'manifest_size')
    _require(hashlib.sha256(raw).hexdigest() == LOCK_SHA256, 'manifest_pin')
    try:
        manifest = json.loads(raw, object_pairs_hook=_unique)
    except (UnicodeError, json.JSONDecodeError):
        raise Rejected('manifest') from None
    _reviewed(manifest)
    _validate_structure(manifest)
    return manifest


def _keys(value, keys, code='manifest_shape'):
    _require(type(value) is dict and set(value) == set(keys.split()), code)


def _package_identity(row):
    _require(type(row['name']) is str and NAME.fullmatch(row['name']), 'package_name')
    _require(type(row['version']) is str and VERSION.fullmatch(row['version']), 'package_version')
    _require(row['architecture'] in ('amd64', 'all'), 'package_architecture')


def _compare_part(left, right):
    """Debian verrevcmp ordering, without invoking dpkg or a native library."""
    def order(char):
        if char == '~':
            return -1
        if not char or char.isdigit():
            return 0
        if char.isalpha():
            return ord(char)
        return ord(char) + 256
    a = b = 0
    while a < len(left) or b < len(right):
        while ((a < len(left) and not left[a].isdigit()) or
               (b < len(right) and not right[b].isdigit())):
            x = order(left[a] if a < len(left) else '')
            y = order(right[b] if b < len(right) else '')
            if x != y:
                return 1 if x > y else -1
            a += a < len(left)
            b += b < len(right)
        while a < len(left) and left[a] == '0':
            a += 1
        while b < len(right) and right[b] == '0':
            b += 1
        start_a, start_b = a, b
        while a < len(left) and left[a].isdigit():
            a += 1
        while b < len(right) and right[b].isdigit():
            b += 1
        x, y = left[start_a:a], right[start_b:b]
        if len(x) != len(y):
            return 1 if len(x) > len(y) else -1
        if x != y:
            return 1 if x > y else -1
    return 0


def compare_versions(left, right):
    """Pure comparison for the restricted Debian version grammar in the lock."""
    def split(value):
        _require(type(value) is str and VERSION.fullmatch(value), 'package_version')
        epoch, sep, rest = value.partition(':')
        if sep:
            _require(epoch.isdigit(), 'package_version')
            epoch = int(epoch)
        else:
            epoch, rest = 0, value
        upstream, sep, revision = rest.rpartition('-')
        return epoch, (upstream if sep else rest), (revision if sep else '0')
    a, b = split(left), split(right)
    return ((a[0] > b[0]) - (a[0] < b[0]) or _compare_part(a[1], b[1])
            or _compare_part(a[2], b[2]))


def _satisfies(actual, operator, required):
    if operator is None:
        return True
    if actual is None:
        return False
    comparison = compare_versions(actual, required)
    return {'<<': comparison < 0, '<=': comparison <= 0, '=': comparison == 0,
            '>=': comparison >= 0, '>>': comparison > 0}[operator]


def _dependency(text):
    match = DEP.fullmatch(text.strip())
    _require(match is not None, 'dependency_grammar')
    return match.groups()


def _closure(packages, roots):
    providers = {}
    for name, row in packages.items():
        if row['provides']:
            for item in row['provides'].split(','):
                virtual, operator, version = _dependency(item)
                _require(operator in (None, '='), 'dependency_provides')
                providers.setdefault(virtual, []).append((name, version))
    seen, pending = set(), list(roots)
    while pending:
        name = pending.pop()
        _require(name in packages, 'dependency_missing')
        if name in seen:
            continue
        seen.add(name)
        for kind in ('pre_depends', 'depends'):
            raw = packages[name][kind]
            for clause in raw.split(',') if raw else ():
                chosen = None
                for alternative in clause.split('|'):
                    dep, operator, version = _dependency(alternative)
                    if dep in packages and _satisfies(packages[dep]['version'], operator, version):
                        chosen = dep
                        break
                    candidates = [(provider, provided) for provider, provided in providers.get(dep, ())
                                  if _satisfies(provided, operator, version)]
                    # Ambiguous virtuals require a real, explicit alternative.
                    if len(candidates) == 1:
                        chosen = candidates[0][0]
                        break
                _require(chosen is not None, 'dependency_missing')
                pending.append(chosen)
    return sorted(seen)


def _validate_structure(manifest):
    """Independent structural/closure checks; public callers also require the pin."""
    _keys(manifest, 'schema_version base_image archive_origin suite architecture provenance '
          'base_packages roots closures sizes packages openssl notes')
    _require(type(manifest['schema_version']) is int and manifest['schema_version'] == 1,
             'manifest_version')
    _require(manifest['base_image'] == BASE_IMAGE and manifest['archive_origin'] == ARCHIVE_ORIGIN
             and manifest['suite'] == 'trixie' and manifest['architecture'] == 'amd64', 'manifest_origin')
    _keys(manifest['provenance'], 'release_sha256 packages_xz_sha256 packages_xz_bytes '
          'signed_release_date signature_fingerprints signature_verification base_manifest_sha256 '
          'base_dpkg_status_sha256 base_inspection')
    _keys(manifest['roots'], 'runtime build')
    _require(manifest['roots'] == {'runtime': ['weston', 'libgl1-mesa-dri', 'openssl'],
                                  'build': ['libweston-14-dev', 'pkgconf', 'gcc', 'libc6-dev']}, 'roots')
    _require(type(manifest['base_packages']) is list and len(manifest['base_packages']) == 87,
             'base_packages')
    base = {}
    for row in manifest['base_packages']:
        _keys(row, 'name version architecture')
        _package_identity(row)
        _require(row['name'] not in base, 'package_duplicate')
        base[row['name']] = row
    _require(type(manifest['packages']) is list and len(manifest['packages']) == 290, 'packages')
    packages = {}
    for row in manifest['packages']:
        _keys(row, 'name version architecture origin path size sha256 installed_kib depends pre_depends provides')
        _package_identity(row)
        name = row['name']
        _require(name not in packages, 'package_duplicate')
        packages[name] = row
        _require(type(row['size']) is int and type(row['installed_kib']) is int
                 and row['installed_kib'] > 0, 'package_size')
        _require(all(type(row[kind]) is str and len(row[kind]) <= 16384
                     for kind in ('depends', 'pre_depends', 'provides')), 'dependency_grammar')
        if name in base:
            _require(row['origin'] == 'pinned-base' and row['path'] is None and row['sha256'] is None
                     and row['size'] == 0 and row['version'] == base[name]['version']
                     and row['architecture'] == base[name]['architecture'], 'base_changed')
        else:
            _require(row['origin'] == 'signed-debian-archive', 'package_origin')
            path = row['path']
            _require(type(path) is str and re.fullmatch(r'pool/main/[a-z0-9][a-z0-9+.-]*/'
                     r'[a-z0-9][a-z0-9+.-]*/[A-Za-z0-9+._~%\-]+\.deb', path), 'package_path')
            _require('/../' not in path and '%' not in path, 'package_path')
            _require(0 < row['size'] <= 128 * 1024 * 1024 and type(row['sha256']) is str
                     and SHA.fullmatch(row['sha256']), 'package_size')
    _keys(manifest['closures'], 'runtime build')
    _keys(manifest['sizes'], 'runtime build')
    for mode in ('runtime', 'build'):
        closure = manifest['closures'][mode]
        _require(type(closure) is list and closure == sorted(set(closure))
                 and closure == _closure(packages, manifest['roots'][mode]), 'closure')
        selected = [packages[name] for name in closure]
        added = [row for row in selected if row['origin'] != 'pinned-base']
        expected = {'base_packages_reused': len(selected) - len(added),
                    'new_packages': len(added), 'download_bytes': sum(row['size'] for row in added),
                    'declared_new_installed_kib': sum(row['installed_kib'] for row in added)}
        _require(manifest['sizes'][mode] == expected, 'closure_size')
    _require(set(packages) == set(manifest['closures']['runtime']) | set(manifest['closures']['build']),
             'package_extra')
    _require(packages['openssl']['version'] == '3.5.7-1~deb13u3'
             and packages['openssl']['origin'] == 'pinned-base', 'base_changed')
    _require(packages['weston']['version'] == packages['libweston-14-dev']['version'] == '14.0.2-1',
             'weston_abi')
    _keys(manifest['openssl'], 'origin package_version upstream_cli_series runtime_cli_version_observed '
          'source_compatibility note')
    _require(manifest['openssl']['runtime_cli_version_observed'] is False, 'unobserved_version')
    # seatd is a hard dependency of libseat1, not a service to run. No logind,
    # Xwayland server or desktop/session package is allowed into either closure.
    _require('seatd' in packages and not {'xwayland', 'systemd', 'systemd-sysv', 'elogind',
             'libpam-systemd', 'gdm3', 'lightdm', 'gnome-shell'} & set(packages), 'package_extra')


def download_plan(manifest):
    """One exact download for each package shared by the two offline stages."""
    _reviewed(manifest)
    result = tuple({'name': row['name'], 'filename': pathlib.PurePosixPath(row['path']).name,
                    'url': ARCHIVE_ORIGIN + row['path'], 'size': row['size'], 'sha256': row['sha256']}
                   for row in manifest['packages'] if row['origin'] != 'pinned-base')
    _require(len(result) == UNION_PACKAGE_COUNT and sum(row['size'] for row in result) == UNION_DOWNLOAD_BYTES
             and len({row['filename'] for row in result}) == len(result), 'download_plan')
    return result


def expected_packages(manifest, mode):
    _reviewed(manifest)
    _require(mode in ('base', 'build', 'runtime'), 'stage')
    rows = list(manifest['base_packages'])
    if mode != 'base':
        closure = set(manifest['closures'][mode])
        rows += [row for row in manifest['packages'] if row['name'] in closure and row['origin'] != 'pinned-base']
    return {row['name']: [row['version'], row['architecture']] for row in rows}


def validate_installed(manifest, mode, output):
    """Pure verifier for dpkg-query's exact tab-separated identity/status output."""
    _require(type(output) is str and len(output) <= 128 * 1024, 'installed_output')
    found = {}
    for line in output.splitlines():
        fields = line.split('\t')
        _require(len(fields) == 4 and fields[3] == 'installed' and fields[0] not in found, 'installed_output')
        found[fields[0]] = fields[1:3]
    _require(found == expected_packages(manifest, mode), 'installed_packages')


def _remaining(deadline, clock=time.monotonic):
    _require(type(deadline) in (int, float) and math.isfinite(deadline), 'deadline')
    remaining = deadline - clock()
    _require(0 < remaining <= MAX_STAGE_SECONDS, 'deadline')
    return remaining


def _curl_command(record, seconds):
    _require(type(record['url']) is str and record['url'].startswith(ARCHIVE_ORIGIN + 'pool/main/')
             and not any(char in record['url'] for char in ('?', '#', '@', '\\', '\n', '\r')),
             'download_origin')
    # -q must be first: never consume ~/.curlrc, proxy credentials or retries.
    return ['/usr/bin/curl', '-q', '--proto', '=https', '--proto-redir', '=https',
            '--noproxy', '*', '--fail', '--silent', '--show-error', '--retry', '0',
            '--connect-timeout', str(min(15, seconds)), '--max-time', str(seconds),
            '--max-filesize', str(record['size']), '--output', '-', '--', record['url']]


def _download(record, stream, deadline, *, clock=time.monotonic):
    """Bounded network primitive, invoked only by the parent's gated CI stage.

    No shell, redirect following, inherited curl configuration, secret env,
    unbounded stdout/stderr, or downloader subprocess descendants. The parent
    reads a pipe with a monotonic deadline and never writes an excess byte;
    curl's independent --max-time also bounds header/DNS/TLS slow-drip cases.
    """
    seconds = min(MAX_DOWNLOAD_SECONDS, _remaining(deadline, clock))
    local_deadline = min(deadline, clock() + seconds)
    process, first_error, cleanup_failed = None, None, False
    digest, total = hashlib.sha256(), 0
    try:
        process = subprocess.Popen(_curl_command(record, seconds), stdin=subprocess.DEVNULL,
                                   stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                                   env={'PATH': '/usr/bin:/bin', 'LC_ALL': 'C'}, close_fds=True)
        with selectors.DefaultSelector() as selector:
            selector.register(process.stdout, selectors.EVENT_READ)
            while True:
                remaining = _remaining(local_deadline, clock)
                _require(bool(selector.select(remaining)), 'download_timeout')
                chunk = os.read(process.stdout.fileno(), min(65536, record['size'] - total + 1))
                _remaining(local_deadline, clock)
                if not chunk:
                    break
                total += len(chunk)
                _require(total <= record['size'], 'download_size')
                stream.write(chunk)
                digest.update(chunk)
        _require(process.wait(timeout=_remaining(local_deadline, clock)) == 0, 'download_failed')
        _require(total == record['size'] and digest.hexdigest() == record['sha256'], 'download_digest')
    except (OSError, subprocess.SubprocessError):
        first_error = Rejected('download_failed')
    except BaseException as error:
        first_error = error
    finally:
        if process is not None:
            running = True
            try:
                running = process.poll() is None
            except Exception:
                cleanup_failed = True
            if running:
                try:
                    process.kill()
                except Exception:
                    cleanup_failed = True
                try:
                    process.wait(timeout=5)
                except Exception:
                    cleanup_failed = True
            try:
                if process.stdout is not None:
                    process.stdout.close()
            except Exception:
                cleanup_failed = True
    _raise_first(first_error, cleanup_failed, 'download_cleanup')


def _raise_first(first_error, cleanup_failed, cleanup_code):
    """Retain first failure; cleanup uncertainty is independent evidence."""
    if first_error is not None:
        if cleanup_failed:
            first_error.cleanup_failed = True
        raise first_error
    if cleanup_failed:
        raise Rejected(cleanup_code, cleanup_failed=True)


def _cleanup_staging(directory, created):
    failed = False
    parents = set()
    for path in created:
        for parent in path.parents:
            if parent == directory:
                break
            parents.add(parent)
        try:
            path.unlink(missing_ok=True)
        except Exception:
            failed = True
    for parent in sorted(parents, key=lambda item: len(item.parts), reverse=True):
        try:
            parent.rmdir()
        except FileNotFoundError:
            pass
        except Exception:
            failed = True
    try:
        directory.rmdir()
    except Exception:
        failed = True
    return failed


def _fresh_directory(target):
    path = pathlib.Path(target)
    _require(path.is_absolute(), 'staging_directory')
    for parent in (path, *path.parents):
        _require(not parent.is_symlink(), 'staging_directory')
    path.mkdir(mode=0o700, parents=False, exist_ok=False)
    return path


def _write_file(path, raw, mode=0o444):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
    with os.fdopen(fd, 'wb') as stream:
        stream.write(raw)
        os.fchmod(stream.fileno(), mode)


def stage_packages(manifest, target, *, deadline):
    """Create a NEW private staging directory. Never reuse an unverified cache.

    On error, files created by this call are removed. All installed state changes
    happen only later, inside the networkless image build, never on this host.
    """
    plan = download_plan(manifest)
    _remaining(deadline)
    directory = _fresh_directory(target)
    created = []
    try:
        for record in plan:
            _remaining(deadline)
            path = directory / ('.' + record['filename'] + '.partial')
            fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
            created.append(path)
            with os.fdopen(fd, 'wb') as stream:
                _download(record, stream, deadline)
                os.fchmod(stream.fileno(), 0o444)
            final = directory / record['filename']
            # Publish only a verified file; linking refuses any existing name.
            os.link(path, final, follow_symlinks=False)
            created.append(final)
            path.unlink()
        return {'files': len(plan), 'bytes': sum(row['size'] for row in plan)}
    except BaseException as error:
        _raise_first(error, _cleanup_staging(directory, created), 'staging_cleanup')


def _select_headers(archive, headers=PRIVATE_HEADERS):
    """Verify archive first; read only five selected regular files, never extractall."""
    _require(type(archive) is bytes and len(archive) == SOURCE_BYTES
             and hashlib.sha256(archive).hexdigest() == SOURCE_SHA256, 'source_digest')
    return _select_verified_headers(archive, headers)


def _select_verified_headers(archive, headers):
    """Inner decoder also used with fabricated archives by pure tests."""
    try:
        decoder = lzma.LZMADecompressor()
        raw = decoder.decompress(archive, max_length=MAX_TAR_BYTES + 1)
        _require(len(raw) <= MAX_TAR_BYTES and decoder.eof and not decoder.unused_data, 'source_limit')
        selected = {}
        with tarfile.open(fileobj=io.BytesIO(raw), mode='r:') as tar:
            for count, member in enumerate(tar, 1):
                _require(count <= MAX_TAR_ENTRIES, 'source_limit')
                name = member.name
                parts = pathlib.PurePosixPath(name).parts
                _require(not name.startswith('/') and '\\' not in name
                         and '..' not in parts and parts and parts[0] == 'weston-14.0.2', 'source_path')
                relative = '/'.join(parts[1:])
                if relative not in headers:
                    continue
                size, sha = headers[relative]
                _require(relative not in selected and member.isfile() and not member.issparse()
                         and member.size == size, 'source_header')
                stream = tar.extractfile(member)
                _require(stream is not None, 'source_header')
                with stream:
                    content = stream.read(size + 1)
                _require(len(content) == size and hashlib.sha256(content).hexdigest() == sha, 'source_header')
                selected[relative] = content
        _require(set(selected) == set(headers), 'source_header')
        return selected
    except (lzma.LZMAError, tarfile.TarError, EOFError, ValueError) as error:
        if isinstance(error, Rejected):
            raise
        raise Rejected('source_archive') from None


def stage_private_headers(target, *, deadline):
    """Keep only hash-checked headers. The source archive never reaches the context."""
    _remaining(deadline)
    stream = io.BytesIO()
    _download({'url': SOURCE_URL, 'size': SOURCE_BYTES, 'sha256': SOURCE_SHA256}, stream, deadline)
    selected = _select_headers(stream.getvalue())
    _remaining(deadline)
    directory = _fresh_directory(target)
    created = []
    try:
        for relative, content in selected.items():
            path = directory / relative
            created.append(path)
            path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
            _write_file(path, content)
        return {'files': len(selected), 'bytes': sum(map(len, selected.values()))}
    except BaseException as error:
        _raise_first(error, _cleanup_staging(directory, created), 'staging_cleanup')


def _pins(pins):
    expected = set(RUNTIME_FILES) | set(ARTIFACT_FILES) | {MODULE_SOURCE}
    _require(type(pins) is dict and set(pins) == expected, 'input_allowlist')
    for row in pins.values():
        _keys(row, 'size sha256', 'input_pin')
        _require(type(row['size']) is int and 0 < row['size'] <= 512 * 1024 * 1024
                 and type(row['sha256']) is str and SHA.fullmatch(row['sha256']), 'input_pin')
    return pins


def render_build_files(manifest, input_pins):
    """Return closed build-context metadata as bytes, without writing/running it.

    Parent supplies reviewed size/hash pins for exactly the module source, four
    runtime scripts, and three independently built executables. No source tree,
    Cargo cache, credentials or fixture contents belong in this build context.
    Expected layout: packages/*.deb, headers/libweston/**, inputs/<allowlist>,
    plus returned Dockerfile/.dockerignore/image-build/* files.
    """
    _reviewed(manifest)
    _pins(input_pins)
    package_rows = {row['name']: row for row in manifest['packages']}
    metadata = {
        'base': expected_packages(manifest, 'base'),
        'build': expected_packages(manifest, 'build'),
        'runtime': expected_packages(manifest, 'runtime'),
        'packages': {mode: [package_rows[name] for name in manifest['closures'][mode]
                           if package_rows[name]['origin'] != 'pinned-base'] for mode in ('build', 'runtime')},
        'inputs': input_pins,
        'headers': {name: {'size': size, 'sha256': sha} for name, (size, sha) in PRIVATE_HEADERS.items()},
    }
    return {'Dockerfile': render_dockerfile(manifest).encode('ascii'),
            '.dockerignore': _dockerignore(manifest).encode('ascii'),
            'image-build/metadata.json': _canonical(metadata) + b'\n',
            'image-build/install.py': _INSTALL_SCRIPT.encode('ascii')}


def _dockerignore(manifest):
    allowed = ['Dockerfile', '.dockerignore', 'image-build/', 'image-build/metadata.json',
               'image-build/install.py', 'packages/', 'headers/', 'headers/libweston/',
               'headers/libweston/backend-drm/', 'inputs/']
    allowed += ['packages/' + row['filename'] for row in download_plan(manifest)]
    allowed += ['headers/' + name for name in PRIVATE_HEADERS]
    allowed += ['inputs/' + name for name in (*RUNTIME_FILES, *ARTIFACT_FILES, MODULE_SOURCE)]
    return '**\n' + ''.join('!' + path + '\n' for path in allowed)


def render_dockerfile(manifest):
    """Two fresh pinned-base stages. Build-time mounts are NOT runtime host mounts."""
    _reviewed(manifest)
    copies = '\n'.join('COPY --chown=0:0 --chmod=' + ('0555' if name in ARTIFACT_FILES else '0444')
                       + ' inputs/' + name + ' ' + ROOT + '/' + name
                       for name in (*RUNTIME_FILES, *ARTIFACT_FILES))
    return f'''# No external/floating Dockerfile frontend, remote ADD, or runtime host mount.
# Requires the reviewed supervisor to build with --network=none, without secrets.
FROM --platform=linux/amd64 {BASE_IMAGE} AS module-build
RUN --network=none --mount=type=bind,source=packages,target=/ci-packages,readonly --mount=type=bind,source=image-build,target=/ci-build,readonly --mount=type=bind,source=headers,target=/ci-headers,readonly --mount=type=bind,source=inputs,target=/ci-inputs,readonly python3 -I -B /ci-build/install.py build
RUN --network=none --mount=type=bind,source=inputs,target=/ci-inputs,readonly --mount=type=bind,source=headers,target=/ci-headers,readonly --mount=type=bind,source=image-build,target=/ci-build,readonly python3 -I -B /ci-build/install.py module
FROM --platform=linux/amd64 {BASE_IMAGE} AS runtime
# seatd is package-present only. policy-rc.d denies service starts; no daemon is launched.
RUN --network=none --mount=type=bind,source=packages,target=/ci-packages,readonly --mount=type=bind,source=image-build,target=/ci-build,readonly --mount=type=bind,source=headers,target=/ci-headers,readonly --mount=type=bind,source=inputs,target=/ci-inputs,readonly python3 -I -B /ci-build/install.py runtime
COPY --from=module-build --chown=0:0 --chmod=0444 /ci-output/{MODULE_BINARY} {ROOT}/{MODULE_BINARY}
COPY --from=module-build --chown=0:0 --chmod=0444 /ci-output/manifest.json {ROOT}/manifest.json
{copies}
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONNOUSERSITE=1
WORKDIR {ROOT}
USER 0:0
ENTRYPOINT ["/usr/local/bin/python3", "-I", "-B", "/opt/ci-ui/ci-ui-container.py"]
'''


# This program is generated into a credential-free build-context file; it is
# never imported or executed by this module or its pure unit tests. It executes
# ONLY in the two RUN --network=none stages after the parent's CI-context gate.
_INSTALL_SCRIPT = r'''import hashlib
import json
import os
import pathlib
import shlex
import shutil
import stat
import subprocess
import sys

ROOT = pathlib.Path('/opt/ci-ui')
LOCK_SHA256 = '2c86592b3b931cb88024205be851caafaa2845f4620d6a950d43d760d94e8127'
RUNTIME_FILES = ('ci-ui-container.py', 'ci-ui-setup-wrapper.py', 'ci-ui-controller.py', 'ci-ui-output.py')
ARTIFACT_FILES = ('coordinator-production', 'coordinator-observed', 'pristine-setup')
ENV = {'PATH': '/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin', 'LC_ALL': 'C',
       'DEBIAN_FRONTEND': 'noninteractive', 'HOME': '/nonexistent'}
PHASE = 'context'
CLEANUP = False

class Failed(Exception):
    def __init__(self, code):
        self.code = code

def need(condition, code):
    if not condition:
        raise Failed(code)

def checked(args, capture=False):
    try:
        result = subprocess.run(args, env=ENV, check=True,
                                stdout=subprocess.PIPE if capture else subprocess.DEVNULL,
                                stderr=subprocess.DEVNULL, timeout=180)
    except subprocess.TimeoutExpired:
        raise Failed('tool_timeout') from None
    except subprocess.CalledProcessError:
        raise Failed('tool_exit') from None
    except OSError:
        raise Failed('tool_start') from None
    if capture:
        need(len(result.stdout) <= 131072, 'tool_output_limit')
    return result.stdout

def installed():
    raw = checked(['dpkg-query', '-W', '-f=${Package}\t${Version}\t${Architecture}\t${db:Status-Status}\n'], capture=True)
    found = {}
    for line in raw.decode('ascii').splitlines():
        fields = line.split('\t')
        need(len(fields) == 4 and fields[3] == 'installed' and fields[0] not in found, 'package_status')
        found[fields[0]] = fields[1:3]
    return found

def verify(path, pin):
    meta = path.lstat()
    need(stat.S_ISREG(meta.st_mode) and meta.st_nlink == 1 and meta.st_size == pin['size'], 'input_file')
    with path.open('rb') as stream:
        need(hashlib.file_digest(stream, 'sha256').hexdigest() == pin['sha256'], 'input_digest')

def processes():
    result = set()
    for path in pathlib.Path('/proc').glob('[0-9]*/stat'):
        try:
            raw = path.read_text()
        except FileNotFoundError:
            continue
        result.add((path.parent.name, raw.rpartition(') ')[2].split()[19]))
    return result

def strip_file_privileges():
    # The package database identities remain pinned, but file modes/xattrs and
    # header contents are intentionally restricted. Not pristine-file equality.
    for current, dirs, files in os.walk('/', topdown=True, followlinks=False):
        if current == '/':
            dirs[:] = [name for name in dirs if name not in
                       ('proc', 'sys', 'dev', 'ci-packages', 'ci-build', 'ci-headers', 'ci-inputs')]
        for name in files:
            path = pathlib.Path(current) / name
            meta = path.lstat()
            if not stat.S_ISREG(meta.st_mode):
                continue
            if meta.st_mode & 0o6000:
                path.chmod(stat.S_IMODE(meta.st_mode) & ~0o6000)
            if 'security.capability' in os.listxattr(path, follow_symlinks=False):
                os.removexattr(path, 'security.capability', follow_symlinks=False)
            need(not path.lstat().st_mode & 0o6000, 'file_privilege')
            need('security.capability' not in os.listxattr(path, follow_symlinks=False), 'file_privilege')

def cleanup():
    for directory in ('/var/lib/apt/lists', '/var/cache/apt', '/var/log/apt', '/tmp', '/var/tmp'):
        if pathlib.Path(directory).exists():
            shutil.rmtree(directory)
        pathlib.Path(directory).mkdir(mode=0o755)
        pathlib.Path(directory).chmod(0o1777 if directory in ('/tmp', '/var/tmp') else 0o755)

def accounts_free():
    for filename, count, id_field in (('/etc/passwd', 7, 2), ('/etc/group', 4, 2)):
        path = pathlib.Path(filename)
        need(path.is_file() and not path.is_symlink(), 'account_file')
        for line in path.read_text().splitlines():
            fields = line.split(':')
            need(len(fields) == count and fields[0] != 'wholepact-ci' and fields[id_field] != '10001', 'account_collision')

def verify_inputs(meta):
    need({p.name for p in pathlib.Path('/ci-inputs').iterdir()} == set(meta['inputs']), 'input_set')
    for name, pin in meta['inputs'].items():
        verify(pathlib.Path('/ci-inputs') / name, pin)
    actual = {str(p.relative_to('/ci-headers')) for p in pathlib.Path('/ci-headers').rglob('*') if p.is_file()}
    need(actual == set(meta['headers']), 'header_set')
    for name, pin in meta['headers'].items():
        verify(pathlib.Path('/ci-headers') / name, pin)

def build_module(meta):
    global PHASE
    PHASE = 'abi'
    need(installed() == meta['build'], 'build_package_set')
    version = checked(['pkg-config', '--modversion', 'libweston-14'], capture=True)
    need(version == b'14.0.2\n', 'weston_abi')
    names = ['libweston-14', 'wayland-server', 'pixman-1', 'xkbcommon']
    cflags = shlex.split(checked(['pkg-config', '--cflags', *names], capture=True).decode('ascii'))
    libs = shlex.split(checked(['pkg-config', '--libs', *names], capture=True).decode('ascii'))
    out = pathlib.Path('/ci-output')
    out.mkdir(mode=0o755, exist_ok=False)
    PHASE = 'compile'
    checked(['gcc', '-std=gnu11', '-O2', '-fPIC', '-fstack-protector-strong', '-D_FORTIFY_SOURCE=2',
             '-Wall', '-Wextra', '-Werror', '-shared', '-Wl,--no-undefined', '-Wl,-z,relro,-z,now',
             '-I/ci-headers/libweston', *cflags, '/ci-inputs/ci-ui-weston-module.c',
             '-o', '/ci-output/ci-ui-weston-module.so', *libs])
    PHASE = 'manifest'
    module = out / 'ci-ui-weston-module.so'
    size = module.stat().st_size
    need(module.is_file() and not module.is_symlink() and 0 < size <= 16 * 1024 * 1024, 'module_file')
    module.chmod(0o444)
    with module.open('rb') as stream:
        module_pin = {'size': size, 'sha256': hashlib.file_digest(stream, 'sha256').hexdigest()}
    files = {name: meta['inputs'][name] for name in (*RUNTIME_FILES, *ARTIFACT_FILES)}
    files['ci-ui-weston-module.so'] = module_pin
    manifest = {'schema_version': 1, 'package_lock_sha256': LOCK_SHA256, 'files': files}
    (out / 'manifest.json').write_text(json.dumps(manifest, sort_keys=True, separators=(',', ':')) + '\n')
    (out / 'manifest.json').chmod(0o444)

def main():
    global PHASE, CLEANUP
    need(len(sys.argv) == 2 and sys.argv[1] in ('build', 'runtime', 'module'), 'arguments')
    mode = sys.argv[1]
    meta = json.loads(pathlib.Path('/ci-build/metadata.json').read_bytes())
    PHASE = 'inputs'
    verify_inputs(meta)
    if mode == 'module':
        build_module(meta)
        return
    PHASE = 'base'
    need(installed() == meta['base'], 'base_package_set')
    need(checked(['dpkg', '--audit'], capture=True) == b'', 'package_audit')
    need(not set(meta['base']) & {'gcc', 'cpp', 'libweston-14-dev', 'libc6-dev', 'pkgconf'}, 'base_build_tools')
    accounts_free()
    base_passwd = pathlib.Path('/etc/passwd').read_bytes()
    PHASE = 'packages'
    all_packages = {pathlib.PurePosixPath(row['path']).name: row
                    for rows in meta['packages'].values() for row in rows}
    need({p.name for p in pathlib.Path('/ci-packages').iterdir()} == set(all_packages), 'package_file_set')
    for filename, row in all_packages.items():
        verify(pathlib.Path('/ci-packages') / filename, row)
    PHASE = 'policy'
    # seatd is package-present only. Deny every service startup/restart request.
    policy = pathlib.Path('/usr/sbin/policy-rc.d')
    need(not policy.is_symlink(), 'service_policy')
    policy.write_text('#!/bin/sh\nexit 101\n')
    policy.chmod(0o755)
    checked(['apt-mark', 'hold', *sorted(meta['base'])])
    before_processes = processes()
    paths = ['/ci-packages/' + pathlib.PurePosixPath(row['path']).name for row in meta['packages'][mode]]
    PHASE = 'install'
    CLEANUP = True
    checked(['apt-get', '--yes', '--no-download', '--no-install-recommends', '--no-install-suggests',
             '--no-remove', '--no-upgrade', '-o', 'Dir::Etc::sourcelist=/dev/null',
             '-o', 'Dir::Etc::sourceparts=-', '-o', 'APT::Get::List-Cleanup=0',
             '-o', 'Dpkg::Use-Pty=0', 'install', *paths])
    PHASE = 'installed'
    need(processes() <= before_processes, 'service_process')
    need(installed() == meta[mode], 'installed_package_set')
    need(checked(['dpkg', '--audit'], capture=True) == b'', 'package_audit')
    need(set(checked(['apt-mark', 'showhold'], capture=True).decode('ascii').splitlines()) == set(meta['base']), 'base_hold_set')
    need(policy.read_text() == '#!/bin/sh\nexit 101\n', 'service_policy')
    if mode == 'runtime':
        PHASE = 'account'
        ROOT.mkdir(mode=0o755, parents=True, exist_ok=False)
        (ROOT / 'base-passwd').write_bytes(base_passwd)
        (ROOT / 'base-passwd').chmod(0o444)
        accounts_free()
        with pathlib.Path('/etc/group').open('a') as stream:
            stream.write('wholepact-ci:x:10001:\n')
        pathlib.Path('/etc/passwd').unlink()
        pathlib.Path('/etc/passwd').symlink_to('/run/ci-account/passwd')
        need(not pathlib.Path('/run/ci-account').exists(), 'account_tmpfs_target')
        PHASE = 'hardening'
        # Even Python's own base headers are excluded from runtime. No new user
        # login, password or credentials are baked in. PID1 owns tmpfs passwd.
        for directory in ('/usr/include', '/usr/local/include'):
            if pathlib.Path(directory).exists():
                shutil.rmtree(directory)
        strip_file_privileges()
        need(installed() == meta['runtime'], 'installed_package_set')

def execute():
    # Only finite phase/check codes are emitted, never native output, exception
    # text, source paths, metadata contents or credentials. Cleanup cannot replace
    # the first failed phase/check. A failed RUN layer is never used as runtime.
    first, cleanup_failed = None, False
    try:
        main()
    except Failed as error:
        first = (PHASE, error.code)
    except Exception:
        first = (PHASE, 'internal')
    if CLEANUP:
        try:
            cleanup()
        except Exception:
            cleanup_failed = True
            if first is None:
                first = ('cleanup', 'cleanup_failed')
    if first is not None:
        print(json.dumps({'schema_version': 1, 'phase': first[0], 'code': first[1],
                          'cleanup_failed': cleanup_failed}, sort_keys=True, separators=(',', ':')),
              file=sys.stderr, flush=True)
        return 1
    return 0

sys.exit(execute())
'''
