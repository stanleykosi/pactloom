#!/usr/bin/env python3
"""Exact-event disposable GitHub UI gate. Import is inert; never a local runner.

The workflow first runs the maintained fixed-origin bootstrap. This supervisor
builds three serial artifacts, runs exactly two containers, and publishes no
success before containers, temporary image and build cache are verified absent.
No credentials, fixture bytes, frames or raw runtime logs leave the containers.
Only pre-credential build failures publish a bounded, scrubbed compiler tail.
"""
import hashlib
import importlib.util
import json
import os
import pathlib
import re
import selectors
import shutil
import signal
import stat
import subprocess
import sys
import tempfile
import time

HERE = pathlib.Path(__file__).resolve().parent
REPO = HERE.parent


def load(name, filename):
    spec = importlib.util.spec_from_file_location(name, HERE / filename)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


B = load('ui_bootstrap_supervisor', 'ci-bootstrap-supervisor.py')
I = load('ui_image', 'ci-ui-image.py')
P = load('ui_output', 'ci-ui-output.py')
BASE = I.BASE_IMAGE
LABEL = 'org.wholepact.ui-run'
SOURCE_LABEL = 'org.wholepact.ui-source'
MODES = ('smoke', 'fixture')
FEATURE = 'coordinated-witness-delivery-append'
FEATURES = {
    'coordinator-production': ['common-image-bootstrap', FEATURE],
    'coordinator-observed': ['common-image-bootstrap', FEATURE],
    'pristine-setup': ['durable-proposal', 'financial-runtime', 'manual-admission',
                       'synthetic-born-joined-qualification'],
}
TMPFS = {
    '/etc/wholepact': 'rw,noexec,nosuid,nodev,size=64k,mode=0755',
    '/run/ci-account': 'rw,noexec,nosuid,nodev,size=64k,mode=0755',
    '/ci-fixture': 'rw,noexec,nosuid,nodev,size=512m,uid=10001,gid=10001,mode=0700',
    '/run/ci-wayland': 'rw,noexec,nosuid,nodev,size=16m,uid=10001,gid=10001,mode=0700',
    '/run/wholepact-delivery-evidence': 'rw,noexec,nosuid,nodev,size=8m,uid=10001,gid=10001,mode=0700',
    '/tmp': 'rw,noexec,nosuid,nodev,size=64m,mode=1777',
    '/dev/shm': 'rw,noexec,nosuid,nodev,size=128m,mode=1777',
}
STAGES = frozenset(('preflight', 'source', 'toolchain', 'prerequisites', 'compile', 'packages', 'image',
                    'container', 'runtime', 'projection', 'cleanup', 'supervisor'))
CHECKS = frozenset(('ci_context', 'architecture', 'arguments', 'source_commit', 'dirty_source',
    'gate_mode', 'toolchain_version', 'command_failed', 'client_deadline', 'output_limit',
    'record_limit', 'tool_start', 'internal', 'interrupted', 'artifact', 'artifact_profile',
    'artifact_features', 'artifact_file', 'artifact_path', 'rustflags', 'input_file',
    'image_identity', 'container_identity', 'container_remaining', 'image_remaining',
    'cache_remaining', 'cleanup_unverified', 'container_status', 'result_records',
    'result_schema', 'result_failure_mismatch', 'staging_rejected', 'image_build',
    'inspect_shape', 'config_shape', 'run_label', 'source_label', 'image_id', 'network',
    'readonly_root', 'privileged', 'cap_drop', 'cap_add', 'no_new_privileges',
    'pids_limit', 'memory_limit', 'swap_limit', 'cpu_limit', 'bind_mounts', 'devices',
    'device_requests', 'extra_mounts', 'image_volumes', 'pid_namespace', 'ipc_namespace',
    'user_namespace', 'cgroup_namespace', 'setup_user', 'supplementary_groups',
    'tmpfs_destinations', 'tmpfs_options', 'log_driver', 'restart_policy', 'ulimits',
    'entrypoint', 'command', 'auto_remove', 'runtime_mounts', 'build_environment',
    'prerequisite_files', 'prerequisite_prefix', 'prerequisite_link', 'prerequisite_versions',
    'prerequisite_tool'))
PACKAGE_CHECKS = frozenset(('duplicate_key', 'manifest', 'manifest_size', 'manifest_pin', 'manifest_shape',
    'manifest_version', 'manifest_origin', 'package_name', 'package_version', 'package_architecture',
    'roots', 'base_packages', 'packages', 'package_duplicate', 'package_size', 'dependency_grammar',
    'base_changed', 'package_origin', 'package_path', 'closure', 'closure_size', 'download_plan',
    'download_origin', 'download_size', 'download_digest', 'download_timeout', 'download_failed',
    'download_cleanup', 'staging_directory', 'staging_cleanup', 'source_digest', 'source_limit',
    'source_path', 'source_header', 'source_archive', 'input_allowlist', 'input_pin', 'deadline',
    'dependency_missing', 'dependency_provides', 'unobserved_version'))
IMAGE_PHASES = frozenset(('context', 'inputs', 'base', 'packages', 'policy', 'install',
                         'installed', 'abi', 'compile', 'manifest', 'account', 'hardening', 'cleanup'))
IMAGE_CHECKS = frozenset(('arguments', 'manifest', 'input_file', 'input_digest', 'input_set',
    'header_set', 'base_package_set', 'base_build_tools', 'base_hold_set', 'build_package_set',
    'installed_package_set', 'package_file_set', 'package_extra', 'package_status',
    'service_policy', 'service_process', 'module_file', 'weston_abi', 'account_collision',
    'account_file', 'account_tmpfs_target', 'file_privilege', 'tool_timeout', 'tool_exit',
    'tool_start', 'tool_output_limit', 'cleanup_failed', 'internal'))


class Failure(Exception):
    def __init__(self, stage, check, output=b'', exit_status=None):
        self.stage = stage if stage in STAGES else 'supervisor'
        self.check = check if check in CHECKS else 'internal'
        self.code = self.check
        self.output = output
        self.exit_status = exit_status
        super().__init__(self.check)


def require(ok, stage, check):
    if not ok:
        raise Failure(stage, check)


def emit(kind, value):
    print('CI_UI_' + kind + ' ' + json.dumps(value, sort_keys=True, separators=(',', ':')), flush=True)


def failure_record(error):
    value = dict(stage=error.stage, check=error.check, expected='satisfied', actual='not_satisfied')
    if getattr(error, 'cause', None) in PACKAGE_CHECKS:
        value['cause'] = error.cause
    if getattr(error, 'cleanup_failed', False):
        value['client_or_staging_cleanup_failed'] = True
    return value


def command(args, stage, *, seconds=20, limit=1024 * 1024, env=None, on_line=None):
    """Bound bytes/client lifetime; cleanup cannot replace the first failure."""
    try:
        process = subprocess.Popen(args, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
            stdin=subprocess.DEVNULL, start_new_session=True, env=env)
    except OSError:
        raise Failure(stage, 'tool_start') from None
    selector, first, status = None, None, None
    output, pending = bytearray(), bytearray()
    deadline, cleanup_failed = time.monotonic() + seconds, False
    try:
        selector = selectors.DefaultSelector()
        selector.register(process.stdout, selectors.EVENT_READ)
        while selector.get_map():
            require(time.monotonic() < deadline, stage, 'client_deadline')
            for key, _ in selector.select(min(.1, max(0, deadline - time.monotonic()))):
                chunk = os.read(key.fileobj.fileno(), 16384)
                if not chunk:
                    selector.unregister(key.fileobj)
                    continue
                require(len(output) + len(chunk) <= limit, stage, 'output_limit')
                output.extend(chunk)
                if on_line is not None:
                    pending.extend(chunk)
                    while b'\n' in pending:
                        line, _, rest = pending.partition(b'\n')
                        require(len(line) <= 8192, stage, 'record_limit')
                        pending[:] = rest
                        on_line(bytes(line))
                    require(len(pending) <= 8192, stage, 'record_limit')
        if on_line is not None and pending:
            on_line(bytes(pending))
        status = process.wait(timeout=max(.01, deadline - time.monotonic()))
    except subprocess.TimeoutExpired:
        first = Failure(stage, 'client_deadline')
    except BaseException as error:
        first = error if isinstance(error, Failure) else Failure(stage, 'internal')
    finally:
        if first is not None:
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            except BaseException:
                cleanup_failed = True
            try:
                process.wait(timeout=5)
            except BaseException:
                cleanup_failed = True
        if selector is not None:
            try:
                selector.close()
            except BaseException:
                cleanup_failed = True
        try:
            process.stdout.close()
        except BaseException:
            cleanup_failed = True
    if cleanup_failed and first is None:
        # A completed nonzero command precedes a later pipe/selector cleanup
        # error. Keep its actual failure, with cleanup uncertainty separate.
        first = Failure(stage, 'command_failed' if status else 'cleanup_unverified')
    if first is not None:
        first.output = bytes(output)
        first.exit_status = process.returncode
        first.cleanup_failed = cleanup_failed
        raise first
    return status, bytes(output)


def checked(args, stage, **kwargs):
    status, output = command(args, stage, **kwargs)
    if status:
        raise Failure(stage, 'command_failed', output, exit_status=status)
    return output


def loads(raw):
    try:
        return B.P.loads(raw)
    except Exception:
        raise Failure('projection', 'result_schema') from None


def context():
    try:
        sha, token = B.context()
    except B.Failure as error:
        raise Failure(error.stage, error.code) from None
    # This exact workflow owns a fresh hosted VM/daemon, never a shared runner.
    require(os.environ.get('GITHUB_JOB') == 'synthetic-only', 'preflight', 'ci_context')
    require(pathlib.Path.cwd().resolve() == REPO, 'preflight', 'ci_context')
    return sha, token


def exact_source(sha):
    require(checked(['git', 'rev-parse', 'HEAD'], 'source', limit=128).strip().decode('ascii') == sha,
            'source', 'source_commit')
    require(checked(['git', 'status', '--porcelain', '--untracked-files=all'], 'source', limit=65536) == b'',
            'source', 'dirty_source')
    require((HERE / 'qualification-gate-mode').read_bytes() == b'ui\n', 'source', 'gate_mode')


BUILD_LOG_LIMIT = 64 * 1024
BUILD_ENV_KEYS = frozenset(('PATH', 'HOME', 'CARGO_HOME', 'CARGO_TARGET_DIR', 'CARGO_BUILD_JOBS',
    'CARGO_INCREMENTAL', 'RUSTUP_HOME', 'RUSTFLAGS', 'WHOLEPACT_BUILD_JOBS',
    'WHOLEPACT_SQLCIPHER_PREFIX', 'SQLCIPHER_LIB_DIR', 'SQLCIPHER_INCLUDE_DIR',
    'SQLCIPHER_STATIC', 'PKG_CONFIG_ALL_STATIC', 'PKG_CONFIG_PATH',
    'GIT_CONFIG_NOSYSTEM', 'GIT_CONFIG_GLOBAL', 'GIT_TERMINAL_PROMPT'))
BUILD_PACKAGES = {name: 'wholepact-native-host' if name == 'pristine-setup'
    else 'wholepact-financial-coordinator' for name in I.ARTIFACT_FILES}
BUILD_PACKAGES['encrypted-storage-prerequisites'] = 'sqlcipher-4.19.0+openssl-3.5.9'
BUILD_TOOLS = ('curl', 'sha256sum', 'tar', 'make', 'gcc', 'perl', 'tclsh', 'pkg-config')


def build_failure_tail(raw):
    """Pre-credential compiler output only, never reusable for runtime logs.

    Builds use a new HOME/CARGO_HOME and explicit credential-free environment.
    No fixture, key, native source setup or container exists at this boundary.
    Preserve dependency/build-script/linker text, including diagnostics without
    primary local spans. JSON escaping prevents workflow-command/terminal input.
    """
    total = len(raw)
    text = raw[-BUILD_LOG_LIMIT:].decode('utf-8', errors='replace')
    text = re.sub(r'github_pat_[A-Za-z0-9_]+|gh[pousr]_[A-Za-z0-9_]+', '[REDACTED]', text)
    text = re.sub(r'(?i)\b(?:bearer|basic)\s+[A-Za-z0-9+/_.=-]+', '[REDACTED]', text)
    text = re.sub(r'(https?://)[^\s/@]+(?::[^\s/@]*)?@', r'\1[REDACTED]@', text)
    text = re.sub(r'(?i)\b([A-Za-z0-9_]*(?:token|password|secret|api_key))\s*[=:]\s*[^\s,;]+',
                  r'\1=[REDACTED]', text)
    text = ''.join(c if c in '\n\t' or (ord(c) >= 32 and ord(c) != 127) else '?' for c in text)
    encoded = text.encode('utf-8')
    shortened = len(encoded) > BUILD_LOG_LIMIT
    text = encoded[-BUILD_LOG_LIMIT:].decode('utf-8', errors='ignore')
    return dict(combined_stdout_stderr_tail=text, tail_bytes=len(text.encode('utf-8')),
                captured_output_bytes=total, tail_truncated=total > BUILD_LOG_LIMIT or shortened)


def compile_failure(error, name, args, environment):
    # Only the pre-credential provider build/checks and three Cargo invocations
    # use this output contract. Runtime/image/install logs remain closed.
    value = dict(schema_version=1, artifact=name, package=BUILD_PACKAGES[name], command=args,
        exit_status=error.exit_status, original_check=error.check, pre_credential=True,
        exit_signal=-error.exit_status if type(error.exit_status) is int and error.exit_status < 0 else None,
        capture_truncated=error.check == 'output_limit',
        client_cleanup_failed=bool(getattr(error, 'cleanup_failed', False)),
        environment_keys=sorted(environment), credential_environment_forwarded=False)
    try:
        value.update(build_failure_tail(error.output))
    except Exception:
        # Preserve exact identity/status/first check even if diagnostic rendering
        # itself fails. Never substitute a cleanup error or an anonymous failure.
        value['diagnostic_unavailable'] = True
    emit('COMPILE_FAILURE', value)


def build_command(name, args, stage, environment, **bounds):
    require(name in BUILD_PACKAGES and set(environment) <= BUILD_ENV_KEYS,
            stage, 'build_environment')
    try:
        return checked(args, stage, env=environment, **bounds)
    except Failure as error:
        compile_failure(error, name, args, environment)
        raise


def encrypted_build_environment(root, environment):
    """Maintained pinned private provider build, before any fixture or container.

    The unchanged recipe also executes its synthetic in-memory version probe in
    isolated CI. It does not create the three-account fixture or install trust.
    Its static OpenSSL 3.5.9 is separate from the image's pinned OpenSSL CLI.
    """
    prefix = root / 'sqlcipher'
    require(re.fullmatch(r'/[A-Za-z0-9_./-]+', str(prefix)) is not None
            and not prefix.exists(), 'prerequisites', 'prerequisite_prefix')
    for tool in BUILD_TOOLS:
        if shutil.which(tool, path=environment['PATH']) is None:
            emit('PREREQUISITE_FAILURE', dict(stage='prerequisites', check='prerequisite_tool',
                missing_tool=tool, pre_credential=True, cleanup_pending=True))
            raise Failure('prerequisites', 'prerequisite_tool')
    selected = dict(environment, WHOLEPACT_SQLCIPHER_PREFIX=str(prefix), WHOLEPACT_BUILD_JOBS='3')
    name = 'encrypted-storage-prerequisites'
    build_command(name, ['bash', 'scripts/build-encrypted-storage-deps.sh'], 'prerequisites', selected,
                  seconds=1500, limit=32 * 1024 * 1024)
    for relative in ('lib/libsqlcipher.a', 'openssl/lib/libcrypto.a', 'include/sqlite3.h',
                     'include/sqlite3ext.h', 'lib/pkgconfig/sqlcipher.pc', 'env.sh', 'build-versions.txt'):
        path = prefix / relative
        require(path.is_file() and not path.is_symlink() and path.stat().st_size > 0
                and path.resolve().is_relative_to(prefix.resolve()), 'prerequisites', 'prerequisite_files')
    expected_env = (f"export SQLCIPHER_LIB_DIR='{prefix}/lib'\n"
        f"export SQLCIPHER_INCLUDE_DIR='{prefix}/include'\n"
        "export SQLCIPHER_STATIC=1\nexport PKG_CONFIG_ALL_STATIC=1\n"
        f"export WHOLEPACT_SQLCIPHER_PREFIX='{prefix}'\n")
    require((prefix / 'env.sh').read_text() == expected_env, 'prerequisites', 'prerequisite_prefix')
    versions = (prefix / 'build-versions.txt').read_text().splitlines()
    require(len(versions) == 3 and versions[0] == '4.19.0 community' and versions[1] == 'openssl'
            and re.fullmatch(r'OpenSSL 3\.5\.9 [0-9]{1,2} [A-Za-z]{3} [0-9]{4}', versions[2]) is not None,
            'prerequisites', 'prerequisite_versions')
    selected.update(SQLCIPHER_LIB_DIR=str(prefix / 'lib'), SQLCIPHER_INCLUDE_DIR=str(prefix / 'include'),
        SQLCIPHER_STATIC='1', PKG_CONFIG_ALL_STATIC='1', PKG_CONFIG_PATH=str(prefix / 'lib/pkgconfig'))
    actual_prefix = build_command(name, ['pkg-config', '--variable=prefix', 'sqlcipher'],
        'prerequisites', selected, seconds=20, limit=4096)
    require(actual_prefix == (str(prefix) + '\n').encode(), 'prerequisites', 'prerequisite_prefix')
    links = build_command(name, ['pkg-config', '--static', '--libs', 'sqlcipher'],
        'prerequisites', selected, seconds=20, limit=4096)
    require(links == f'-L{prefix}/lib -lsqlcipher -L{prefix}/openssl/lib -lcrypto -ldl -lpthread -lm \n'.encode(),
            'prerequisites', 'prerequisite_link')
    emit('PREREQUISITES', dict(sqlcipher='4.19.0', static_openssl='3.5.9', private_static_prefix=True,
        synthetic_in_memory_version_probe=True, pre_credential=True, fixture_created=False))
    return selected


def select_artifact(raw, name, target):
    """Use only this invocation's compiler report, including the Host LIB test."""
    setup = name == 'pristine-setup'
    wanted = 'wholepact_native_host' if setup else 'wholepact-financial-coordinator'
    found = []
    for line in raw.splitlines():
        require(len(line) <= 2 * 1024 * 1024, 'compile', 'record_limit')
        try:
            row = json.loads(line)
        except (ValueError, UnicodeDecodeError):
            continue
        if type(row) is not dict or row.get('reason') != 'compiler-artifact':
            continue
        item = row.get('target', {})
        if type(item) is not dict or item.get('name') != wanted or not row.get('executable'):
            continue
        require(item.get('kind') == (['lib'] if setup else ['bin']), 'compile', 'artifact_profile')
        profile = row.get('profile', {})
        require(type(profile) is dict and profile.get('test') is setup and profile.get('opt_level') == '3'
                and profile.get('debug_assertions') is False, 'compile', 'artifact_profile')
        require(row.get('features') == FEATURES[name], 'compile', 'artifact_features')
        executable = row['executable']
        require(type(executable) is str, 'compile', 'artifact_path')
        path = pathlib.Path(executable)
        require(path.is_absolute() and not path.is_symlink(), 'compile', 'artifact_path')
        resolved = path.resolve(strict=True)
        require(resolved.is_relative_to(target.resolve(strict=True)), 'compile', 'artifact_path')
        meta = path.lstat()
        require(stat.S_ISREG(meta.st_mode) and 0 < meta.st_size <= 512 * 1024 * 1024,
                'compile', 'artifact_file')
        found.append(path)
    require(len(found) == 1, 'compile', 'artifact')
    return found[0]


def pin(path):
    meta = path.stat(follow_symlinks=False)
    require(stat.S_ISREG(meta.st_mode) and 0 < meta.st_size <= 512 * 1024 * 1024,
            'source', 'input_file')
    with path.open('rb') as stream:
        return dict(size=meta.st_size, sha256=hashlib.file_digest(stream, 'sha256').hexdigest())


def build_inputs(root, sha):
    build_context = root / 'context'
    inputs = build_context / 'inputs'
    inputs.mkdir(parents=True)
    for folder in ('home', 'cargo', 'target'):
        (root / folder).mkdir()
    env = dict(PATH=os.environ['PATH'], HOME=str(root / 'home'), CARGO_HOME=str(root / 'cargo'),
        CARGO_TARGET_DIR=str(root / 'target'), CARGO_BUILD_JOBS='3', CARGO_INCREMENTAL='0',
        RUSTUP_HOME=os.environ.get('RUSTUP_HOME', str(pathlib.Path.home() / '.rustup')),
        GIT_CONFIG_NOSYSTEM='1', GIT_CONFIG_GLOBAL='/dev/null', GIT_TERMINAL_PROMPT='0')
    checked(['rustup', 'toolchain', 'install', '1.99.0', '--profile', 'minimal', '--no-self-update'],
            'toolchain', seconds=600, limit=4 * 1024 * 1024, env=env)
    require(checked(['rustup', 'run', '1.99.0', 'rustc', '--version'], 'toolchain', env=env).decode().strip() == B.RUSTC,
            'toolchain', 'toolchain_version')
    exact_source(sha)
    env = encrypted_build_environment(root, env)
    pins = {}
    # Serial invocations only. Cargo fingerprints features/cfgs; snapshot each
    # current compiler-selected executable before any following build can run.
    for name in I.ARTIFACT_FILES:
        exact_source(sha)
        selected = dict(env)
        setup = name == 'pristine-setup'
        if name == 'coordinator-observed':
            selected['RUSTFLAGS'] = '--cfg wholepact_delivery_ci'
        require(selected.get('RUSTFLAGS') == ('--cfg wholepact_delivery_ci' if name == 'coordinator-observed' else None),
                'compile', 'rustflags')
        args = ['rustup', 'run', '1.99.0', 'cargo', 'test' if setup else 'build']
        if setup:
            args += ['--no-run']
        args += ['--locked', '--release', '--no-default-features', '-p',
                 'wholepact-native-host' if setup else 'wholepact-financial-coordinator']
        args += ['--lib'] if setup else ['--bin', 'wholepact-financial-coordinator']
        args += ['--features', 'durable-proposal,synthetic-born-joined-qualification' if setup else FEATURE,
                 '--message-format=json']
        raw = build_command(name, args, 'compile', selected, seconds=1800, limit=32 * 1024 * 1024)
        artifact = select_artifact(raw, name, root / 'target')
        shutil.copyfile(artifact, inputs / name)
        (inputs / name).chmod(0o555)
        pins[name] = pin(inputs / name)
        emit('ARTIFACT', dict(artifact=name, source=sha, sha256=pins[name]['sha256'],
                              ci_instrumented=name == 'coordinator-observed', setup_test=setup))
    for name in (*I.RUNTIME_FILES, I.MODULE_SOURCE):
        shutil.copyfile(HERE / name, inputs / name)
        (inputs / name).chmod(0o444)
        pins[name] = pin(inputs / name)
    try:
        lock = I.validate_manifest((HERE / 'ci-ui-packages.json').read_bytes())
        deadline = time.monotonic() + 900
        I.stage_packages(lock, build_context / 'packages', deadline=deadline)
        I.stage_private_headers(build_context / 'headers', deadline=deadline)
        for relative, raw in I.render_build_files(lock, pins).items():
            path = build_context / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(raw)
            path.chmod(0o444)
    except I.Rejected as error:
        failure = Failure('packages', 'staging_rejected')
        failure.cause = error.code if error.code in PACKAGE_CHECKS else None
        failure.cleanup_failed = bool(getattr(error, 'cleanup_failed', False))
        raise failure from None
    exact_source(sha)
    return build_context, pins


def docker_env():
    return dict(PATH=os.environ['PATH'], HOME='/nonexistent', DOCKER_HOST='unix:///var/run/docker.sock',
                DOCKER_CONFIG=os.environ['UI_DOCKER_CONFIG'], DOCKER_BUILDKIT='1')


def docker(args, stage, **kwargs):
    return checked(['docker'] + args, stage, env=docker_env(), **kwargs)


def names(token):
    raw = docker(['ps', '--all', '--format', '{{.Names}}', '--filter', 'label=' + LABEL + '=' + token],
                 'cleanup', limit=4096)
    try:
        values = raw.decode('ascii').splitlines()
    except UnicodeError:
        raise Failure('cleanup', 'container_identity') from None
    expected = {'wp-ui-' + token + '-' + mode for mode in MODES}
    require(len(values) <= 2 and len(values) == len(set(values)) and set(values) <= expected,
            'cleanup', 'container_identity')
    return values


def remove_container(name, token):
    first, should_remove = None, False
    try:
        should_remove = name in names(token)
    except Failure as error:
        # Failed listing cannot prevent killing/removing this exact attempted name.
        first, should_remove = error, True
    if should_remove:
        try:
            try:
                docker(['kill', '--signal', 'KILL', name], 'cleanup')
            except Failure:
                pass
            docker(['rm', '--force', '--volumes', name], 'cleanup')
        except Failure as error:
            first = first or error
    try:
        require(name not in names(token), 'cleanup', 'container_remaining')
        raw = docker(['ps', '--all', '--format', '{{.Names}}', '--filter', 'name=^/' + name + '$'],
                     'cleanup', limit=4096)
        require(not raw.strip(), 'cleanup', 'container_remaining')
    except Failure as error:
        first = first or error
    if first:
        raise first


def isolation(mode, check, ok, expected, actual):
    if not ok:
        emit('FAILURE', dict(mode=mode, stage='container', check=check,
             expected=expected, actual=actual, cleanup_pending=True))
        error = Failure('container', check)
        error.published = True
        raise error


def inspect_isolation(name, token, mode, image_id, sha):
    raw = docker(['inspect', '--type', 'container', name], 'container', limit=65536)
    try:
        rows = loads(raw)
    except Failure:
        isolation(mode, 'inspect_shape', False, 'one_container_object', 'invalid_json')
    isolation(mode, 'inspect_shape', type(rows) is list and len(rows) == 1 and type(rows[0]) is dict,
              'one_container_object', 'invalid_shape')
    row = rows[0]
    cfg, host = row.get('Config'), row.get('HostConfig')
    isolation(mode, 'config_shape', type(cfg) is dict and type(host) is dict,
              'config_and_host_objects', 'invalid_shape')
    checks = {
        'run_label': type(cfg.get('Labels')) is dict and cfg['Labels'].get(LABEL) == token,
        'source_label': type(cfg.get('Labels')) is dict and cfg['Labels'].get(SOURCE_LABEL) == sha,
        'image_id': row.get('Image') == image_id and cfg.get('Image') == image_id,
        'network': host.get('NetworkMode') == 'none',
        'readonly_root': host.get('ReadonlyRootfs') is True,
        'privileged': host.get('Privileged') is False,
        'cap_drop': host.get('CapDrop') == ['ALL'],
        'no_new_privileges': host.get('SecurityOpt') == ['no-new-privileges:true'],
        'pid_namespace': host.get('PidMode') == '',
        'ipc_namespace': host.get('IpcMode') == 'private',
        'user_namespace': host.get('UsernsMode') == '',
        'cgroup_namespace': host.get('CgroupnsMode') == 'private',
        'setup_user': cfg.get('User') == '0:0',
        'supplementary_groups': B.absent(host.get('GroupAdd')),
        'log_driver': host.get('LogConfig') == {'Type': 'none', 'Config': {}},
        'restart_policy': host.get('RestartPolicy') == {'Name': 'no', 'MaximumRetryCount': 0},
        'auto_remove': host.get('AutoRemove') is False,
        'entrypoint': cfg.get('Entrypoint') == ['/usr/local/bin/python3', '-I', '-B', '/opt/ci-ui/ci-ui-container.py'],
        'command': cfg.get('Cmd') == [mode],
    }
    for check, ok in checks.items():
        isolation(mode, check, ok, 'exact_contract', 'exact_contract' if ok else 'different_or_invalid')
    caps = host.get('CapAdd')
    aliases = {'SETUID': 'SETUID', 'CAP_SETUID': 'SETUID', 'SETGID': 'SETGID', 'CAP_SETGID': 'SETGID'}
    normalized = [aliases.get(item) if type(item) is str else None for item in caps] if type(caps) is list else []
    isolation(mode, 'cap_add', type(caps) is list and len(caps) == 2 and set(normalized) == {'SETUID', 'SETGID'},
              ['SETUID', 'SETGID'], B.finite_list(caps, set(aliases)))
    for check, field, expected in (('pids_limit', 'PidsLimit', 128), ('memory_limit', 'Memory', 2 * 1024**3),
            ('swap_limit', 'MemorySwap', 2 * 1024**3), ('cpu_limit', 'NanoCpus', 2_000_000_000)):
        value = host.get(field)
        isolation(mode, check, type(value) is int and value == expected, expected, B.finite_number(value))
    for check, value in (('bind_mounts', host.get('Binds')), ('devices', host.get('Devices')),
            ('device_requests', host.get('DeviceRequests')), ('extra_mounts', host.get('Mounts')),
            ('image_volumes', cfg.get('Volumes'))):
        ok = B.absent(value) or (check == 'image_volumes' and value == {})
        isolation(mode, check, ok, 'absent', 'absent' if ok else 'present_or_invalid')
    actual_mounts = row.get('Mounts')
    mounts_ok = type(actual_mounts) is list and all(type(mount) is dict and mount.get('Type') == 'tmpfs'
        and mount.get('Destination') in TMPFS and not mount.get('Source') for mount in actual_mounts)
    isolation(mode, 'runtime_mounts', mounts_ok, 'tmpfs_only', 'tmpfs_only' if mounts_ok else 'other_or_invalid')
    value = host.get('Tmpfs')
    isolation(mode, 'tmpfs_destinations', type(value) is dict and set(value) == set(TMPFS),
              'exact_seven_tmpfs', 'exact_seven_tmpfs' if type(value) is dict and set(value) == set(TMPFS) else 'missing_extra_or_invalid')
    for path, expected in TMPFS.items():
        parts = value[path].split(',') if type(value[path]) is str else []
        ok = len(parts) == len(set(parts)) and set(parts) == set(expected.split(','))
        isolation(mode, 'tmpfs_options', ok, 'exact_mount_options', 'exact_mount_options' if ok else 'different_or_invalid')
    limits = host.get('Ulimits')
    expected = [{'Name': 'core', 'Hard': 0, 'Soft': 0}, {'Name': 'nofile', 'Hard': 512, 'Soft': 512}]
    ok = type(limits) is list and len(limits) == 2 and all(item in expected for item in limits) and limits[0] != limits[1]
    isolation(mode, 'ulimits', ok, 'core_0_nofile_512', 'core_0_nofile_512' if ok else 'different_or_invalid')


class RuntimeRecords:
    def __init__(self, mode):
        self.mode, self.first_failure, self.result = mode, None, None

    def __call__(self, line):
        require(type(line) is bytes and 0 < len(line) <= 8192, 'projection', 'result_records')
        if line.startswith(b'CI_UI_FAILURE '):
            require(self.first_failure is None and self.result is None, 'projection', 'result_records')
            try:
                value = P.validate_failure(loads(line[len(b'CI_UI_FAILURE '):]), self.mode)
            except Exception:
                raise Failure('projection', 'result_schema') from None
            self.first_failure = value
            emit('FAILURE', value)
        else:
            require(self.result is None, 'projection', 'result_records')
            try:
                self.result = P.validate_runtime_result(loads(line), self.mode)
            except Exception:
                raise Failure('projection', 'result_schema') from None
            if self.result['outcome'] != 'passed' and self.first_failure is None:
                self.first_failure = self.result['first_failure']
                emit('FAILURE', self.first_failure)

    def finish(self, status):
        require(self.result is not None, 'projection', 'result_records')
        result = self.result
        require(status == (0 if result['outcome'] == 'passed' else 1), 'runtime', 'container_status')
        require(self.first_failure is None or result['first_failure'] == self.first_failure,
                'projection', 'result_failure_mismatch')
        if result['outcome'] != 'passed' and self.first_failure is None:
            self.first_failure = result['first_failure']
            emit('FAILURE', self.first_failure)
        return result


def run_case(mode, image_id, token, sha):
    name = 'wp-ui-' + token + '-' + mode
    records = RuntimeRecords(mode)
    removed, create_pending, result, first = False, False, None, None
    try:
        require(name not in names(token), 'container', 'container_identity')
        create_pending = True
        args = ['create', '--pull', 'never', '--name', name, '--label', LABEL + '=' + token,
            '--label', SOURCE_LABEL + '=' + sha, '--network', 'none', '--read-only', '--cap-drop', 'ALL',
            '--cap-add', 'SETUID', '--cap-add', 'SETGID', '--security-opt', 'no-new-privileges:true',
            '--pids-limit', '128', '--memory', '2g', '--memory-swap', '2g', '--cpus', '2',
            '--ipc', 'private', '--cgroupns', 'private', '--ulimit', 'core=0:0', '--ulimit', 'nofile=512:512',
            '--log-driver', 'none', '--restart', 'no']
        for path, options in TMPFS.items():
            args += ['--tmpfs', path + ':' + options]
        docker(args + [image_id, mode], 'container', limit=4096)
        create_pending = False
        inspect_isolation(name, token, mode, image_id, sha)
        status, _ = command(['docker', 'start', '--attach', name], 'runtime', env=docker_env(),
            seconds=150 if mode == 'smoke' else 930, limit=16384, on_line=records)
        result = records.finish(status)
    except Failure as error:
        first = error
        if records.first_failure is None and not getattr(error, 'published', False):
            emit('FAILURE', dict(mode=mode, **failure_record(error), cleanup_pending=True))
    except Exception:
        first = Failure('supervisor', 'internal')
        if records.first_failure is None:
            emit('FAILURE', dict(mode=mode, **failure_record(first), cleanup_pending=True))
    finally:
        try:
            remove_container(name, token)
            removed = not create_pending
        except Failure as error:
            if first is None and records.first_failure is None:
                emit('FAILURE', dict(mode=mode, **failure_record(error), cleanup_pending=True))
            first = first or error
    return result, bool(result and result['outcome'] == 'passed' and removed and first is None)


def image_failure(raw):
    for line in raw.splitlines():
        if len(line) > 8192:
            continue
        start = line.find(b'{')
        if start < 0:
            continue
        try:
            value = loads(line[start:])
        except Failure:
            continue
        if (type(value) is dict and set(value) == {'schema_version', 'phase', 'code', 'cleanup_failed'}
                and type(value['schema_version']) is int and value['schema_version'] == 1
                and type(value['phase']) is str and value['phase'] in IMAGE_PHASES
                and type(value['code']) is str and value['code'] in IMAGE_CHECKS
                and type(value['cleanup_failed']) is bool):
            emit('FAILURE', dict(stage='image', check='image_build', phase=value['phase'],
                code=value['code'], image_stage_cleanup_failed=value['cleanup_failed'], cleanup_pending=True))
            return True
    return False


def cache_empty(raw):
    try:
        rows = [loads(line) for line in raw.splitlines()]
    except Failure:
        return False
    rows = [row for row in rows if type(row) is dict and row.get('Type') == 'Build Cache']
    return (len(rows) == 1 and type(rows[0].get('TotalCount')) in (int, str)
            and rows[0]['TotalCount'] in (0, '0') and rows[0].get('Size') == '0B')


def cleanup(token, tag):
    containers_absent, image_absent, cache_absent = True, True, True
    # Always reconcile both deterministic owned names, including uncertain creates.
    for mode in MODES:
        try:
            remove_container('wp-ui-' + token + '-' + mode, token)
        except Failure:
            containers_absent = False
    try:
        containers_absent = not names(token) and containers_absent
    except Failure:
        containers_absent = False
    try:
        label_ids = docker(['image', 'ls', '--quiet', '--no-trunc', '--filter', 'label=' + LABEL + '=' + token],
                           'cleanup', limit=4096).splitlines()
        tag_ids = docker(['image', 'ls', '--quiet', '--no-trunc', '--filter', 'reference=' + tag],
                         'cleanup', limit=4096).splitlines()
        require(len(label_ids) <= 1 and len(tag_ids) <= 1 and label_ids == tag_ids,
                'cleanup', 'image_identity')
        if label_ids:
            require(re.fullmatch(b'sha256:[0-9a-f]{64}', label_ids[0]) is not None, 'cleanup', 'image_identity')
            docker(['image', 'rm', '--force', tag], 'cleanup')
        require(not docker(['image', 'ls', '--quiet', '--filter', 'label=' + LABEL + '=' + token],
                           'cleanup', limit=4096).strip(), 'cleanup', 'image_remaining')
        require(not docker(['image', 'ls', '--quiet', '--filter', 'reference=' + tag],
                           'cleanup', limit=4096).strip(), 'cleanup', 'image_remaining')
    except Failure:
        image_absent = False
    try:
        # Only on the exact dedicated disposable hosted daemon checked by context().
        docker(['builder', 'prune', '--all', '--force'], 'cleanup', seconds=120, limit=1024 * 1024)
        require(cache_empty(docker(['system', 'df', '--format', '{{json .}}'], 'cleanup',
                                  seconds=30, limit=16384)), 'cleanup', 'cache_remaining')
    except Failure:
        cache_absent = False
    emit('CLEANUP', dict(containers_absent=containers_absent, temporary_image_absent=image_absent,
                         build_cache_absent=cache_absent, source_runtime_cleanup_claim=False))
    return containers_absent and image_absent and cache_absent


def main():
    sha, token = context()
    require(len(sys.argv) == 2 and sys.argv[1] in ('run', 'cleanup'), 'preflight', 'arguments')
    cleanup_only = sys.argv[1] == 'cleanup'
    tag = 'wholepact-ui:' + token
    root = pathlib.Path(tempfile.mkdtemp(prefix='wholepact-ui-', dir=os.environ['RUNNER_TEMP']))
    (root / 'docker').mkdir()
    os.environ['UI_DOCKER_CONFIG'] = str(root / 'docker')
    passed, first, results = cleanup_only, None, []
    try:
        if not cleanup_only:
            exact_source(sha)
            emit('SOURCE', dict(source=sha, toolchain='1.99.0', container_base=BASE,
                package_lock_sha256=I.LOCK_SHA256,
                cargo_lock_sha256=hashlib.sha256((REPO / 'Cargo.lock').read_bytes()).hexdigest(),
                fixture_count=1, synthetic_accounts=3, fixture_ceiling_seconds=900, case_ceiling_seconds=120,
                runtime_identity_contract=dict(uid=10001, gid=10001, supplementary_groups=[],
                    active_cap_sets_zero=['CapInh', 'CapPrm', 'CapEff', 'CapAmb'], bounding_cap_hex='00000000000000c0',
                    setup_caps=['SETUID', 'SETGID'], no_new_privileges=True),
                resource_contract=dict(pids_including_threads=128, memory_bytes=2 * 1024**3, cpus=2),
                financial_suite_rerun=False, public_chain_verified=False, user_installation=False))
            build_context, _ = build_inputs(root, sha)
            docker(['pull', '--platform', 'linux/amd64', BASE], 'image', seconds=300, limit=4 * 1024 * 1024)
            try:
                docker(['build', '--network', 'none', '--no-cache', '--force-rm', '--progress', 'plain',
                    '--label', LABEL + '=' + token, '--label', SOURCE_LABEL + '=' + sha,
                    '--tag', tag, str(build_context)], 'image', seconds=900, limit=8 * 1024 * 1024)
            except Failure as error:
                error.published = image_failure(error.output)
                raise
            image_id = docker(['image', 'inspect', '--format', '{{.Id}}', tag], 'image', limit=128).strip().decode('ascii')
            require(re.fullmatch('sha256:[0-9a-f]{64}', image_id) is not None, 'image', 'image_identity')
            exact_source(sha)
            passed = True
            for mode in MODES:
                result, ok = run_case(mode, image_id, token, sha)
                if result is not None:
                    results.append(result)
                if not ok:
                    passed = False
                    break
    except Failure as error:
        first = failure_record(error)
        if not getattr(error, 'published', False):
            emit('FAILURE', dict(**first, cleanup_pending=True))
    except Exception:
        first = failure_record(Failure('supervisor', 'internal'))
        emit('FAILURE', dict(**first, cleanup_pending=True))
    finally:
        clean = cleanup(token, tag)
        try:
            shutil.rmtree(root)
        except OSError:
            clean = False
        passed = passed and clean and first is None
        if cleanup_only:
            emit('CLEANUP_RESULT', dict(cleanup_passed=passed, cleanup_only=True, source=sha,
                                        lifecycle_result='not_evaluated'))
        else:
            if passed:
                for result in results:
                    emit('CASE', result)
            emit('RESULT', dict(passed=passed, source=sha, ui_only=True, single_synthetic_fixture=True,
                containers_and_image_removed=clean, historical_ci64_financial_revalidated=False,
                public_chain_verified=False, deployment_verified=False, full_product_verified=False))
    return 0 if passed else 1


if __name__ == '__main__':
    def interrupted(_signum, _frame):
        raise Failure('supervisor', 'interrupted')
    signal.signal(signal.SIGTERM, interrupted)
    signal.signal(signal.SIGINT, interrupted)
    try:
        sys.exit(main())
    except Exception:
        emit('FAILURE', dict(stage='preflight', check='ci_context', expected='isolated_ci', actual='not_established'))
        sys.exit(1)
