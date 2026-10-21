#!/usr/bin/env python3
"""Bootstrap-only CI build and whole-container supervisor. Never a local runner.

Official base provenance (retrieved 2026-10-21):
https://raw.githubusercontent.com/docker-library/repo-info/master/repos/python/remote/3.13-slim-trixie.md
linux/amd64 Python 3.13.16 manifest below; immutable image, no apt/pip/RUN.
"""
import hashlib
import importlib.util
import json
import os
import pathlib
import platform
import re
import selectors
import shutil
import signal
import subprocess
import sys
import tempfile
import time

HERE = pathlib.Path(__file__).resolve().parent
SPEC = importlib.util.spec_from_file_location('bootstrap_projection', HERE / 'ci-bootstrap-output.py')
P = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(P)
BASE = 'docker.io/library/python@sha256:8fb4cfa1a2616d7b8e0c2175cc6ad68f5729c34ea8488c0b360d2934b7be9024'
RUSTC = 'rustc 1.99.0 (b940084d7 2026-09-28)'
LABEL = 'org.wholepact.bootstrap-run'
DOCKER_TIMEOUT = 20


class Failure(Exception):
    def __init__(self, stage, code, output=b''):
        self.stage, self.code, self.output = stage, code, output


def require(ok, stage, code):
    if not ok:
        raise Failure(stage, code)


def command(args, stage, seconds=DOCKER_TIMEOUT, limit=1024 * 1024, env=None):
    """Bound both pipe bytes and client lifetime, withholding all raw text.

Killing this exact client session does NOT kill Docker's container. Callers
always independently remove the tracked container, even on this exception.
"""
    process = subprocess.Popen(args, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                               stdin=subprocess.DEVNULL, start_new_session=True, env=env)
    selector = selectors.DefaultSelector()
    selector.register(process.stdout, selectors.EVENT_READ)
    output = bytearray()
    deadline = time.monotonic() + seconds
    failure = None
    try:
        while selector.get_map():
            if time.monotonic() >= deadline:
                raise Failure(stage, 'client_deadline', bytes(output))
            for key, _ in selector.select(min(.1, max(0, deadline - time.monotonic()))):
                chunk = os.read(key.fileobj.fileno(), 16384)
                if not chunk:
                    selector.unregister(key.fileobj)
                    continue
                if len(output) + len(chunk) > limit:
                    raise Failure(stage, 'output_limit', bytes(output))
                output.extend(chunk)
        status = process.wait(timeout=max(.1, deadline - time.monotonic()))
        return status, bytes(output)
    except subprocess.TimeoutExpired:
        failure = Failure(stage, 'client_deadline', bytes(output))
        raise failure
    except BaseException as error:
        failure = error
        raise
    finally:
        if failure is not None:
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                pass
        selector.close()
        process.stdout.close()


def checked(args, stage, **kwargs):
    status, output = command(args, stage, **kwargs)
    if status != 0:
        raise Failure(stage, 'command_failed', output)
    return output


def context():
    require(os.environ.get('GITHUB_ACTIONS') == 'true' and os.environ.get('RUNNER_OS') == 'Linux'
            and os.environ.get('RUNNER_ENVIRONMENT') == 'github-hosted', 'preflight', 'ci_context')
    require(os.environ.get('GITHUB_REPOSITORY') == 'stanleykosi/pactloom'
            and os.environ.get('GITHUB_REF') == 'refs/heads/qualification/durable-proposal-v1'
            and os.environ.get('GITHUB_EVENT_NAME') == 'push', 'preflight', 'ci_context')
    sha = os.environ.get('GITHUB_SHA', '')
    run = os.environ.get('GITHUB_RUN_ID', '')
    attempt = os.environ.get('GITHUB_RUN_ATTEMPT', '')
    require(P.SHA.fullmatch(sha) is not None and re.fullmatch('[1-9][0-9]{0,19}', run) is not None
            and re.fullmatch('[1-9][0-9]{0,5}', attempt) is not None, 'preflight', 'ci_context')
    require(platform.machine() == 'x86_64', 'preflight', 'architecture')
    return sha, run + '-' + attempt + '-' + sha


def exact_source(sha):
    require(checked(['git', 'rev-parse', 'HEAD'], 'source', limit=128).strip().decode('ascii') == sha,
            'source', 'source_commit')
    require(checked(['git', 'status', '--porcelain', '--untracked-files=all'], 'source', limit=65536) == b'',
            'source', 'dirty_source')
    # UI qualification runs this exact bootstrap prerequisite before its own gate.
    require((HERE / 'qualification-gate-mode').read_bytes() in (b'bootstrap\n', b'ui\n'),
            'source', 'gate_mode')


def emit(kind, value):
    print('CI_BOOTSTRAP_' + kind + ' ' + json.dumps(value, sort_keys=True, separators=(',', ':')), flush=True)


def compile_errors(raw):
    sources = set(checked(['git', 'ls-files', '--', 'crates/wholepact-financial-coordinator',
                          'crates/wholepact-financial-coordinator-origin'],
                          'source', limit=65536).decode('ascii').splitlines())
    seen = set()
    for line in raw.splitlines():
        if len(line) > 2 * 1024 * 1024:
            continue
        try:
            row = json.loads(line)
            msg = row.get('message', {})
            if row.get('reason') != 'compiler-message' or msg.get('level') != 'error':
                continue
            code = (msg.get('code') or {}).get('code', 'Uncoded')
            if not isinstance(code, str) or re.fullmatch('E[0-9]{4}', code) is None:
                code = 'Uncoded'
            for span in msg.get('spans', [])[:64]:
                name, number = span.get('file_name'), span.get('line_start')
                if span.get('is_primary') is True and name in sources and type(number) is int and 0 < number < 100000:
                    key = (code, name, number)
                    if key not in seen and len(seen) < 20:
                        seen.add(key)
                        emit('COMPILE', dict(code=code, source=name, line=number))
        except (ValueError, TypeError, AttributeError):
            continue


def build(root, sha):
    images = root / 'context' / 'images'
    images.mkdir(parents=True)
    images.chmod(0o755)
    images.parent.chmod(0o755)
    for folder in ('home', 'cargo', 'target', 'docker'):
        (root / folder).mkdir()
    # Empty HOME/CARGO_HOME means no developer registry credentials or caches.
    # The official numbered toolchain is the sole existing runner tool input.
    env = dict(PATH=os.environ['PATH'], HOME=str(root / 'home'), CARGO_HOME=str(root / 'cargo'),
               CARGO_TARGET_DIR=str(root / 'target'), CARGO_BUILD_JOBS='3', CARGO_INCREMENTAL='0',
               RUSTUP_HOME=os.environ.get('RUSTUP_HOME', str(pathlib.Path.home() / '.rustup')))
    checked(['rustup', 'toolchain', 'install', '1.99.0', '--profile', 'minimal', '--no-self-update'],
            'toolchain', seconds=600, limit=4 * 1024 * 1024, env=env)
    require(checked(['rustup', 'run', '1.99.0', 'rustc', '--version'], 'toolchain', env=env).decode().strip() == RUSTC,
            'toolchain', 'toolchain_version')
    hashes = {}
    for case in P.CASES:
        exact_source(sha)
        selected = dict(env)
        if case != 'production':
            selected['RUSTFLAGS'] = '--cfg wholepact_bootstrap_ci'
            selected['WHOLEPACT_BOOTSTRAP_CI_CASE'] = case
        args = ['rustup', 'run', '1.99.0', 'cargo', 'build', '--locked', '--no-default-features',
                '-p', 'wholepact-financial-coordinator', '--features', 'common-image-bootstrap',
                '--bin', 'wholepact-financial-coordinator', '--message-format=json']
        try:
            raw = checked(args, 'compile', seconds=600, limit=16 * 1024 * 1024, env=selected)
        except Failure as error:
            compile_errors(error.output)
            raise
        artifacts = []
        for line in raw.splitlines():
            try:
                row = json.loads(line)
            except (ValueError, UnicodeDecodeError):
                continue
            if row.get('reason') == 'compiler-artifact' and row.get('target', {}).get('name') == 'wholepact-financial-coordinator' and row.get('executable'):
                require(row.get('profile', {}).get('test') is False, 'compile', 'test_artifact')
                artifacts.append(pathlib.Path(row['executable']).resolve(strict=True))
        require(len(set(artifacts)) == 1, 'compile', 'artifact')
        exe = artifacts[0]
        require(exe.is_relative_to((root / 'target').resolve()) and exe.is_file(), 'compile', 'artifact')
        shutil.copyfile(exe, images / case)
        (images / case).chmod(0o555)
        with (images / case).open('rb') as stream:
            hashes[case] = hashlib.file_digest(stream, 'sha256').hexdigest()
        emit('IMAGE', dict(case=case, sha256=hashes[case], source=sha, ci_instrumented=case != 'production'))
    manifest = dict(schema_version=1, source=sha, images=hashes)
    (root / 'context' / 'manifest.json').write_text(json.dumps(manifest, separators=(',', ':'), sort_keys=True))
    for name in ('ci-bootstrap-container.py', 'ci-bootstrap-output.py'):
        shutil.copyfile(HERE / name, root / 'context' / name)
        (root / 'context' / name).chmod(0o444)
    (root / 'context' / 'manifest.json').chmod(0o444)
    (root / 'context' / 'Dockerfile').write_text(
        'FROM ' + BASE + '\nCOPY --chown=0:0 . /opt/bootstrap/\n'
        'ENTRYPOINT ["/usr/local/bin/python3","-I","-B","/opt/bootstrap/ci-bootstrap-container.py"]\n')
    return root / 'context'


def docker(args, stage, **kwargs):
    # No personal Docker credentials/context. The runner's local daemon is the
    # only selected endpoint; neither host socket nor credentials enter runtime.
    env = dict(PATH=os.environ['PATH'], HOME='/nonexistent', DOCKER_HOST='unix:///var/run/docker.sock',
               DOCKER_CONFIG=os.environ['BOOTSTRAP_DOCKER_CONFIG'])
    return checked(['docker'] + args, stage, env=env, **kwargs)


def owned_names(token):
    raw = docker(['ps', '--all', '--format', '{{.Names}}', '--filter', 'label=' + LABEL + '=' + token],
                 'cleanup', limit=4096)
    names = raw.decode('ascii').splitlines()
    prefix = 'wp-bootstrap-' + token + '-'
    require(len(names) <= len(P.CASES) and all(name.startswith(prefix) and name[len(prefix):] in P.CASES for name in names),
            'cleanup', 'container_identity')
    return names


def remove_container(name, token):
    # rm --force asks the daemon to kill the whole container, not its CLI. A
    # separate successful listing is mandatory even after rm client failure.
    first = None
    try:
        names = owned_names(token)
        if name in names:
            try:
                docker(['kill', '--signal', 'KILL', name], 'cleanup')
            except Failure:
                pass  # An already exited container needs no kill, but must be removed.
            docker(['rm', '--force', '--volumes', name], 'cleanup')
    except Failure as error:
        first = error
    try:
        require(name not in owned_names(token), 'cleanup', 'container_remaining')
    except Failure as error:
        if first is None:
            first = error
    if first is not None:
        raise first


def finite_list(value, allowed):
    if value is None: return 'null'
    if type(value) is not list: return 'invalid_type'
    if len(value) > 16: return 'oversized'
    return [item if type(item) is str and item in allowed else 'other' for item in value]


def finite_number(value):
    return value if type(value) is int and 0 <= value <= 2**40 else 'invalid_or_out_of_range'


def finite_bool(value):
    return value if type(value) is bool else 'invalid_type'


def absent(value):
    return value is None or (type(value) is list and not value)


def isolation_check(case, field, ok, expected, observed):
    if not ok:
        # Both projections come only from the closed vocabulary at each call;
        # never print arbitrary inspect strings, paths, labels or environment.
        emit('ISOLATION_FAILURE', dict(case=case, check=field, expected=expected,
                                       observed=observed, cleanup_pending=True))
        raise Failure('container', 'isolation_' + field)


def inspect_isolation(name, token, case):
    raw = docker(['inspect', '--type', 'container', name], 'container', limit=65536)
    try:
        values = P.loads(raw)
    except P.Rejected:
        isolation_check(case, 'inspect_shape', False, 'one_container_object', 'invalid_json')
    isolation_check(case, 'inspect_shape', type(values) is list and len(values) == 1
                    and type(values[0]) is dict, 'one_container_object', 'wrong_container_shape')
    row = values[0]
    cfg, host = row.get('Config'), row.get('HostConfig')
    isolation_check(case, 'config_shape', type(cfg) is dict and type(host) is dict,
                    'config_and_host_objects', 'invalid_config_shape')
    labels = cfg.get('Labels')
    matching_label = type(labels) is dict and labels.get(LABEL) == token
    isolation_check(case, 'run_label', matching_label, 'matching_run_label',
                    'matching_run_label' if matching_label else 'missing_or_different_run_label')
    value = host.get('NetworkMode')
    isolation_check(case, 'network', value == 'none', 'none', value if value in ('none', 'host', 'bridge', 'default', '') else 'other')
    value = host.get('ReadonlyRootfs')
    isolation_check(case, 'readonly_root', value is True, True, finite_bool(value))
    value = host.get('Privileged')
    isolation_check(case, 'privileged', value is False, False, finite_bool(value))
    value = host.get('CapDrop')
    isolation_check(case, 'cap_drop', value == ['ALL'], ['ALL'], finite_list(value, {'ALL'}))
    value = host.get('CapAdd')
    # Official ContainerCreate normalizes SETUID to CAP_SETUID (and SETGID):
    # https://raw.githubusercontent.com/moby/moby/v28.5.2/client/container_create.go
    # https://raw.githubusercontent.com/docker/cli/v28.5.2/opts/capabilities.go
    # Accept only these four exact spellings, preserving cardinality and rejecting
    # aliases duplicated in one list. No case-folding or unknown capability passes.
    aliases = {'SETUID': 'SETUID', 'CAP_SETUID': 'SETUID', 'SETGID': 'SETGID', 'CAP_SETGID': 'SETGID'}
    normalized = [aliases.get(item) if type(item) is str else None for item in value] if type(value) is list else []
    isolation_check(case, 'cap_add', type(value) is list and len(value) == 2
                    and set(normalized) == {'SETUID', 'SETGID'}, ['SETUID', 'SETGID'], finite_list(value, set(aliases)))
    value = host.get('SecurityOpt')
    isolation_check(case, 'no_new_privileges', value == ['no-new-privileges:true'], ['no-new-privileges:true'],
                    finite_list(value, {'no-new-privileges:true', 'no-new-privileges=false',
                                        'no-new-privileges=true', 'seccomp=unconfined', 'apparmor=unconfined'}))
    for field, key, expected in [('pids_limit', 'PidsLimit', 64), ('memory_limit', 'Memory', 256 * 1024 * 1024)]:
        value = host.get(key)
        isolation_check(case, field, type(value) is int and value == expected, expected, finite_number(value))
    for field, value in [('bind_mounts', host.get('Binds')), ('devices', host.get('Devices')),
                         ('extra_mounts', host.get('Mounts')), ('image_volumes', cfg.get('Volumes'))]:
        # Config.Volumes is a Go map, whereas the HostConfig fields are slices.
        is_absent = absent(value) or (field == 'image_volumes' and type(value) is dict and not value)
        isolation_check(case, field, is_absent, 'absent', 'absent' if is_absent else 'present_or_invalid')
    value = host.get('PidMode')
    isolation_check(case, 'pid_namespace', value == '', 'private_default',
                    'private_default' if value == '' else 'host' if value == 'host' else 'other')
    value = cfg.get('User')
    isolation_check(case, 'setup_user', value == '', 'image_default_root',
                    'image_default_root' if value == '' else 'other')
    value = host.get('Tmpfs')
    expected = {'/etc/wholepact': 'rw,noexec,nosuid,nodev,size=64k,mode=0755',
                '/ci-evidence': 'rw,noexec,nosuid,nodev,size=1m,uid=10001,gid=10001,mode=0700',
                '/tmp': 'rw,noexec,nosuid,nodev,size=1m,mode=1777'}
    isolation_check(case, 'tmpfs_destinations', type(value) is dict and set(value) == set(expected),
                    'pin_evidence_tmp_only', 'pin_evidence_tmp_only' if type(value) is dict and set(value) == set(expected) else 'missing_extra_or_invalid')
    for path, field in [('/etc/wholepact', 'pin_tmpfs'), ('/ci-evidence', 'evidence_tmpfs'), ('/tmp', 'runtime_tmpfs')]:
        options = value[path]
        parts = options.split(',') if type(options) is str else []
        same = len(parts) == len(set(parts)) and set(parts) == set(expected[path].split(','))
        expected_parts = expected[path].split(',')
        isolation_check(case, field, same, expected_parts,
                        finite_list(parts, set(expected_parts)) if type(options) is str else 'invalid_type')


def run_case(case, tag, token):
    name = 'wp-bootstrap-' + token + '-' + case
    first = None
    result = P.result(case, 'error', 'container', 'container_create')
    removed = False
    create_pending = False
    try:
        require(name not in owned_names(token), 'container', 'container_identity')
        # Name is known before create; an uncertain create/start is never retried.
        create_pending = True
        docker(['create', '--pull', 'never', '--name', name, '--label', LABEL + '=' + token,
                '--network', 'none', '--read-only', '--cap-drop', 'ALL', '--cap-add', 'SETUID', '--cap-add', 'SETGID',
                '--security-opt', 'no-new-privileges:true', '--pids-limit', '64', '--memory', '256m', '--memory-swap', '256m',
                '--cpus', '2', '--ulimit', 'core=0:0', '--ulimit', 'nofile=256:256', '--log-driver', 'none',
                '--tmpfs', '/etc/wholepact:rw,noexec,nosuid,nodev,size=64k,mode=0755',
                '--tmpfs', '/ci-evidence:rw,noexec,nosuid,nodev,size=1m,uid=10001,gid=10001,mode=0700',
                '--tmpfs', '/tmp:rw,noexec,nosuid,nodev,size=1m,mode=1777', tag, case], 'container', limit=4096)
        create_pending = False
        inspect_isolation(name, token, case)
        # start --attach may time out while runtime continues. The finally block
        # always kills/removes the known container independently of this client.
        status, raw = command(['docker', '--host', 'unix:///var/run/docker.sock', '--config', os.environ['BOOTSTRAP_DOCKER_CONFIG'],
                               'start', '--attach', name], 'runtime', seconds=60, limit=8192)
        result = P.validate_result(P.loads(raw), case)
        require(status == (0 if result['outcome'] == 'passed' else 1), 'runtime', 'container_status')
    except (Failure, P.Rejected) as error:
        first = error
        result = P.result(case, 'error', getattr(error, 'stage', 'projection'), error.code)
    except Exception:
        first = Failure('projection', 'internal')
        result = P.result(case, 'error', 'projection', 'internal')
    finally:
        if result['outcome'] != 'passed':
            emit('CASE_FAILURE', dict(case=case, stage=result['stage'], code=result['code'], cleanup_pending=True,
                                      **{key: result[key] for key in P.OBSERVATION_FIELDS}))
        try:
            remove_container(name, token)
            # A timed-out create might still be pending in the daemon. A later
            # always-cleanup pass will reconcile, but this result cannot claim
            # definite removal solely from a currently empty listing.
            removed = not create_pending
        except Failure:
            # A cleanup error must not erase the first runtime/schema failure.
            if result['outcome'] == 'passed':
                result = P.result(case, 'error', 'cleanup', 'container_unverified')
                emit('CASE_FAILURE', dict(case=case, stage='cleanup', code='container_unverified', cleanup_pending=True))
        result['container_removed'] = removed
        emit('CASE', result)
    return result['outcome'] == 'passed' and removed and first is None


def cleanup(token, tag):
    containers_absent = True
    image_absent = True
    try:
        for name in owned_names(token):
            try:
                remove_container(name, token)
            except Failure:
                containers_absent = False
        containers_absent = not owned_names(token) and containers_absent
    except Failure:
        containers_absent = False
    try:
        images = docker(['image', 'ls', '--quiet', '--filter', 'label=' + LABEL + '=' + token], 'cleanup', limit=4096).splitlines()
        require(len(images) <= 1, 'cleanup', 'image_identity')
        if images:
            docker(['image', 'rm', '--force', tag], 'cleanup')
        require(not docker(['image', 'ls', '--quiet', '--filter', 'label=' + LABEL + '=' + token], 'cleanup', limit=4096).strip(),
                'cleanup', 'image_remaining')
    except Failure:
        image_absent = False
    emit('CLEANUP', dict(containers_absent=containers_absent, temporary_image_absent=image_absent,
                         source_runtime_cleanup_claim=False))
    return containers_absent and image_absent


def main():
    sha, token = context()
    tag = 'wholepact-bootstrap:' + token
    root = pathlib.Path(tempfile.mkdtemp(prefix='wholepact-bootstrap-', dir=os.environ['RUNNER_TEMP']))
    (root / 'docker').mkdir()
    os.environ['BOOTSTRAP_DOCKER_CONFIG'] = str(root / 'docker')
    passed = False
    first = None
    cleanup_only = len(sys.argv) == 2 and sys.argv[1] == 'cleanup'
    try:
        require(len(sys.argv) == 2 and sys.argv[1] in ('run', 'cleanup'), 'preflight', 'arguments')
        if sys.argv[1] == 'cleanup':
            passed = True
        else:
            exact_source(sha)
            emit('SOURCE', dict(source=sha, toolchain='1.99.0', container_base=BASE,
                                cargo_lock_sha256=hashlib.sha256(pathlib.Path('Cargo.lock').read_bytes()).hexdigest(),
                                financial_qualification_run=False, origin_qualification_run=False,
                                runtime_identity_contract=dict(setup_caps=['SETUID', 'SETGID'],
                                    active_cap_sets_zero=True, bounding_ceiling=['SETUID', 'SETGID'],
                                    no_new_privileges=True, uid=10001, supplementary_groups=[])))
            # build() wants its own fresh empty Docker config directory.
            (root / 'docker').rmdir()
            build_context = build(root, sha)
            docker(['pull', '--platform', 'linux/amd64', BASE], 'image', seconds=300, limit=4 * 1024 * 1024)
            docker(['build', '--network', 'none', '--no-cache', '--force-rm', '--label', LABEL + '=' + token,
                    '--tag', tag, str(build_context)], 'image', seconds=300, limit=4 * 1024 * 1024)
            exact_source(sha)
            passed = all(run_case(case, tag, token) for case in P.CASES)
    except Failure as error:
        first = dict(stage=error.stage, code=error.code)
        emit('FAILURE', first)
    except Exception:
        first = dict(stage='supervisor', code='internal')
        emit('FAILURE', first)
    finally:
        clean = cleanup(token, tag)
        shutil.rmtree(root)
        passed = passed and clean and first is None
        if cleanup_only:
            emit('CLEANUP_RESULT', dict(cleanup_passed=passed, cleanup_only=True, source=sha,
                                        lifecycle_result='not_evaluated'))
        else:
            emit('RESULT', dict(passed=passed, source=sha, bootstrap_only=True,
                                financial_authority=False, native_payment_verified=False,
                                public_chain_verified=False, full_product_verified=False))
    return 0 if passed else 1


if __name__ == '__main__':
    def interrupted(_signum, _frame):
        raise Failure('supervisor', 'interrupted')
    signal.signal(signal.SIGTERM, interrupted)
    signal.signal(signal.SIGINT, interrupted)
    try:
        sys.exit(main())
    except Exception:
        emit('FAILURE', dict(stage='preflight', code='ci_context'))
        sys.exit(1)
