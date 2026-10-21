#!/usr/bin/env python3
"""Pure fabricated-record/mocked-control tests. No native/product/socket runner."""
import contextlib
import importlib.util
import io
import json
import pathlib
import tempfile
import unittest
from unittest import mock

ROOT = pathlib.Path(__file__).parents[1]
SPEC = importlib.util.spec_from_file_location('ci_ui_supervisor_tested', ROOT / 'ci-ui-supervisor.py')
S = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(S)


def inspect_fixture():
    return [dict(Image='sha256:' + 'a' * 64, Mounts=[], Config=dict(
        Labels={S.LABEL: 'token', S.SOURCE_LABEL: 'b' * 40}, Image='sha256:' + 'a' * 64,
        User='0:0', Volumes=None, Entrypoint=['/usr/local/bin/python3', '-I', '-B', '/opt/ci-ui/ci-ui-container.py'],
        Cmd=['smoke']), HostConfig=dict(NetworkMode='none', ReadonlyRootfs=True, Privileged=False,
        CapDrop=['ALL'], CapAdd=['CAP_SETGID', 'CAP_SETUID'], SecurityOpt=['no-new-privileges:true'],
        PidsLimit=128, Memory=2 * 1024**3, MemorySwap=2 * 1024**3, NanoCpus=2_000_000_000,
        Binds=None, Devices=[], DeviceRequests=None, Mounts=None, PidMode='', IpcMode='private',
        UsernsMode='', CgroupnsMode='private', GroupAdd=None, Tmpfs=dict(S.TMPFS),
        LogConfig={'Type': 'none', 'Config': {}}, RestartPolicy={'Name': 'no', 'MaximumRetryCount': 0},
        AutoRemove=False, Ulimits=[{'Name': 'core', 'Soft': 0, 'Hard': 0},
                                 {'Name': 'nofile', 'Soft': 512, 'Hard': 512}]))]


class Isolation(unittest.TestCase):
    def check(self, rows, field=None):
        output = io.StringIO()
        with mock.patch.object(S, 'docker', return_value=json.dumps(rows).encode()), contextlib.redirect_stdout(output):
            if field is None:
                S.inspect_isolation('name', 'token', 'smoke', 'sha256:' + 'a' * 64, 'b' * 40)
                self.assertEqual(output.getvalue(), '')
                return
            with self.assertRaises(S.Failure) as failed:
                S.inspect_isolation('name', 'token', 'smoke', 'sha256:' + 'a' * 64, 'b' * 40)
        self.assertEqual(failed.exception.check, field)
        self.assertNotIn('PRIVATE_SENTINEL', output.getvalue())
        record = json.loads(output.getvalue().split(' ', 1)[1])
        self.assertEqual(record['check'], field)
        self.assertTrue(record['cleanup_pending'])

    def test_exact_isolation_and_canonical_capabilities(self):
        for caps in (['CAP_SETUID', 'CAP_SETGID'], ['SETGID', 'SETUID']):
            rows = inspect_fixture(); rows[0]['HostConfig']['CapAdd'] = caps; self.check(rows)

    def test_rejects_added_capabilities_or_duplicate_aliases(self):
        for caps in (None, [], ['SETUID'], ['SETUID', 'CAP_SETUID'], ['SETUID', 'SETGID', 'SETPCAP'],
                     ['CAP_SETGID', 'PRIVATE_SENTINEL'], [False, 'SETUID']):
            rows = inspect_fixture(); rows[0]['HostConfig']['CapAdd'] = caps; self.check(rows, 'cap_add')

    def test_resource_bounds_are_exact_and_never_relaxed(self):
        for key, check in [('PidsLimit', 'pids_limit'), ('Memory', 'memory_limit'),
                           ('MemorySwap', 'swap_limit'), ('NanoCpus', 'cpu_limit')]:
            for value in (None, True, 0, 2**50, 'PRIVATE_SENTINEL'):
                rows = inspect_fixture(); rows[0]['HostConfig'][key] = value; self.check(rows, check)

    def test_no_host_mounts_or_devices(self):
        for key, check in [('Binds', 'bind_mounts'), ('Devices', 'devices'),
                           ('DeviceRequests', 'device_requests'), ('Mounts', 'extra_mounts')]:
            rows = inspect_fixture(); rows[0]['HostConfig'][key] = ['PRIVATE_SENTINEL']; self.check(rows, check)
        rows = inspect_fixture(); rows[0]['Mounts'] = [{'Type': 'bind', 'Source': 'PRIVATE_SENTINEL'}]
        self.check(rows, 'runtime_mounts')

    def test_exact_tmpfs_destinations_and_options(self):
        rows = inspect_fixture(); rows[0]['HostConfig']['Tmpfs']['PRIVATE_SENTINEL'] = 'rw'
        self.check(rows, 'tmpfs_destinations')
        for destination in S.TMPFS:
            rows = inspect_fixture(); rows[0]['HostConfig']['Tmpfs'][destination] += ',exec'
            self.check(rows, 'tmpfs_options')
            rows = inspect_fixture(); value = rows[0]['HostConfig']['Tmpfs'][destination]
            rows[0]['HostConfig']['Tmpfs'][destination] = ','.join(reversed(value.split(',')))
            self.check(rows)

    def test_unknown_shape_or_duplicate_json_fails_closed(self):
        self.check([], 'inspect_shape')
        rows = inspect_fixture(); rows[0]['Config'] = None; self.check(rows, 'config_shape')
        with mock.patch.object(S, 'docker', return_value=b'[{"Config":{},"Config":{}}]'), contextlib.redirect_stdout(io.StringIO()):
            with self.assertRaises(S.Failure) as caught:
                S.inspect_isolation('name', 'token', 'smoke', 'sha256:' + 'a' * 64, 'b' * 40)
            self.assertEqual(caught.exception.check, 'inspect_shape')


def artifact_row(path, name='pristine-setup'):
    setup = name == 'pristine-setup'
    return dict(reason='compiler-artifact', executable=str(path), features=list(S.FEATURES[name]),
        target=dict(name='wholepact_native_host' if setup else 'wholepact-financial-coordinator',
                    kind=['lib'] if setup else ['bin']),
        profile=dict(test=setup, opt_level='3', debug_assertions=False))


class BuildSelection(unittest.TestCase):
    def test_exact_library_test_and_product_artifacts(self):
        with tempfile.TemporaryDirectory() as directory:
            target = pathlib.Path(directory)
            artifact = target / 'executable'; artifact.write_bytes(b'not executable')
            for name in S.I.ARTIFACT_FILES:
                row = artifact_row(artifact, name)
                self.assertEqual(S.select_artifact(json.dumps(row).encode(), name, target), artifact)

    def test_zero_test_binary_feature_drift_and_debug_are_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            target = pathlib.Path(directory)
            artifact = target / 'executable'; artifact.write_bytes(b'inert')
            for field in ('kind', 'test', 'features', 'opt_level'):
                row = artifact_row(artifact)
                if field == 'kind': row['target']['kind'] = ['bin']
                if field == 'test': row['profile']['test'] = False
                if field == 'features': row['features'] += ['default']
                if field == 'opt_level': row['profile']['opt_level'] = '0'
                with self.assertRaises(S.Failure):
                    S.select_artifact(json.dumps(row).encode(), 'pristine-setup', target)

    def test_artifact_outside_target_and_duplicate_reports_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory); target = root / 'target'; target.mkdir()
            artifact = root / 'outside'; artifact.write_bytes(b'inert')
            with self.assertRaises(S.Failure):
                S.select_artifact(json.dumps(artifact_row(artifact)).encode(), 'pristine-setup', target)
            artifact = target / 'inside'; artifact.write_bytes(b'inert')
            row = json.dumps(artifact_row(artifact)).encode()
            with self.assertRaises(S.Failure): S.select_artifact(row + b'\n' + row, 'pristine-setup', target)

    def test_build_commands_are_serial_positive_feature_and_host_lib_test(self):
        source = (ROOT / 'ci-ui-supervisor.py').read_text()
        self.assertIn("args += ['--lib'] if setup", source)
        self.assertIn("'--locked', '--release', '--no-default-features'", source)
        self.assertIn("selected['RUSTFLAGS'] = '--cfg wholepact_delivery_ci'", source)
        self.assertLess(source.index('shutil.copyfile(artifact'), source.index('pins[name] = pin(inputs / name)', source.index('def build_inputs(')))
        self.assertIn("CARGO_TARGET_DIR=str(root / 'target')", source)


class ClientCleanup(unittest.TestCase):
    def test_first_failure_survives_each_cleanup_exception(self):
        # Every process/selector operation is mocked. No fd/socket/process exists.
        for broken in ('kill', 'wait', 'selector_close', 'stdout_close'):
            process, selector = mock.Mock(), mock.Mock()
            process.pid = 123
            process.stdout.fileno.return_value = 456
            selector.get_map.return_value = {1: True}
            key = mock.Mock(fileobj=process.stdout)
            selector.select.return_value = [(key, None)]
            original = S.Failure('runtime', 'record_limit')
            def on_line(_): raise original
            if broken == 'wait': process.wait.side_effect = OSError('PRIVATE_SENTINEL')
            if broken == 'selector_close': selector.close.side_effect = OSError('PRIVATE_SENTINEL')
            if broken == 'stdout_close': process.stdout.close.side_effect = OSError('PRIVATE_SENTINEL')
            kill = OSError('PRIVATE_SENTINEL') if broken == 'kill' else None
            with mock.patch.object(S.subprocess, 'Popen', return_value=process), \
                 mock.patch.object(S.selectors, 'DefaultSelector', return_value=selector), \
                 mock.patch.object(S.os, 'read', return_value=b'bounded\n'), \
                 mock.patch.object(S.os, 'killpg', side_effect=kill), \
                 self.assertRaises(S.Failure) as caught:
                S.command(['inert'], 'runtime', on_line=on_line)
            self.assertIs(caught.exception, original)
            self.assertTrue(original.cleanup_failed)
            self.assertEqual(original.output, b'bounded\n')
            self.assertNotIn('PRIVATE_SENTINEL', json.dumps(S.failure_record(original)))

    def test_cleanup_failure_cannot_turn_success_into_pass(self):
        process, selector = mock.Mock(), mock.Mock()
        process.wait.return_value = 0
        selector.get_map.return_value = {}
        process.stdout.close.side_effect = OSError('PRIVATE_SENTINEL')
        with mock.patch.object(S.subprocess, 'Popen', return_value=process), \
             mock.patch.object(S.selectors, 'DefaultSelector', return_value=selector), \
             self.assertRaises(S.Failure) as caught:
            S.command(['inert'], 'image')
        self.assertEqual(caught.exception.check, 'cleanup_unverified')
        self.assertTrue(caught.exception.cleanup_failed)

    def test_nonzero_exit_survives_later_pipe_cleanup_failure(self):
        process, selector = mock.Mock(), mock.Mock()
        process.wait.return_value = process.returncode = 101
        selector.get_map.return_value = {}
        process.stdout.close.side_effect = OSError('later cleanup failure')
        with mock.patch.object(S.subprocess, 'Popen', return_value=process), \
             mock.patch.object(S.selectors, 'DefaultSelector', return_value=selector), \
             self.assertRaises(S.Failure) as caught:
            S.command(['inert'], 'compile')
        self.assertEqual(caught.exception.check, 'command_failed')
        self.assertEqual(caught.exception.exit_status, 101)
        self.assertTrue(caught.exception.cleanup_failed)

    def test_staging_cause_is_closed_and_cleanup_separate(self):
        error = S.Failure('packages', 'staging_rejected')
        error.cause, error.cleanup_failed = 'download_digest', True
        value = S.failure_record(error)
        self.assertEqual(value['cause'], 'download_digest')
        self.assertTrue(value['client_or_staging_cleanup_failed'])
        error.cause = 'PRIVATE_SENTINEL'
        self.assertNotIn('PRIVATE_SENTINEL', json.dumps(S.failure_record(error)))


class PreCredentialDiagnostics(unittest.TestCase):
    def test_dependency_linker_and_build_script_text_survive_without_local_spans(self):
        output = io.StringIO()
        raw = b'error: failed to run custom build command\nld: cannot find -lsqlcipher\nno primary spans\n'
        error = S.Failure('compile', 'command_failed', raw, exit_status=101)
        args = ['rustup', 'run', '1.99.0', 'cargo', 'build']
        with mock.patch.object(S, 'checked', side_effect=error), contextlib.redirect_stdout(output):
            with self.assertRaises(S.Failure) as caught:
                S.build_command('coordinator-production', args, 'compile', {'HOME': '/fresh'})
        self.assertIs(caught.exception, error)
        row = json.loads(output.getvalue().split(' ', 1)[1])
        self.assertEqual(row['combined_stdout_stderr_tail'], raw.decode())
        self.assertEqual(row['command'], args)
        self.assertEqual(row['package'], 'wholepact-financial-coordinator')
        self.assertEqual(row['exit_status'], 101)
        self.assertFalse(row['capture_truncated'])
        self.assertTrue(row['pre_credential'])

    def test_tail_bound_utf8_and_capture_limit_are_distinct(self):
        raw = b'old' * 40000 + ('\u2603' * 30000).encode()
        value = S.build_failure_tail(raw)
        self.assertLessEqual(value['tail_bytes'], 65536)
        self.assertEqual(value['captured_output_bytes'], len(raw))
        self.assertTrue(value['tail_truncated'])
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            S.compile_failure(S.Failure('compile', 'output_limit', b'captured', -9),
                'coordinator-observed', ['cargo'], {})
        row = json.loads(output.getvalue().split(' ', 1)[1])
        self.assertTrue(row['capture_truncated'])
        self.assertEqual(row['exit_signal'], 9)
        self.assertEqual(row['original_check'], 'output_limit')
        self.assertNotIn('total_output_bytes', row)

    def test_accidental_tokens_userinfo_and_controls_are_scrubbed_and_json_escaped(self):
        raw = (b'github_pat_private ghp_private Authorization: Bearer private '
               b'Basic cHJpdmF0ZQ== https://user:private@example.test/path '
               b'GITHUB_TOKEN=private API_KEY:private\x1b[31m\x00\r\n::error::not a workflow command\n')
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            S.compile_failure(S.Failure('compile', 'command_failed', raw, 1),
                'pristine-setup', ['cargo', 'test', '--no-run'], {})
        self.assertEqual(len(output.getvalue().splitlines()), 1)
        self.assertNotIn('private', output.getvalue())
        row = json.loads(output.getvalue().split(' ', 1)[1])
        self.assertIn('[REDACTED]', row['combined_stdout_stderr_tail'])
        for control in ('\x1b', '\x00', '\r'):
            self.assertNotIn(control, row['combined_stdout_stderr_tail'])

    def test_projector_fallback_preserves_exact_identity_and_first_failure(self):
        output = io.StringIO()
        error = S.Failure('compile', 'client_deadline', b'prior', -9)
        error.cleanup_failed = True
        with mock.patch.object(S, 'build_failure_tail', side_effect=ValueError()), contextlib.redirect_stdout(output):
            S.compile_failure(error, 'pristine-setup', ['cargo', 'test', '--no-run'], {})
        row = json.loads(output.getvalue().split(' ', 1)[1])
        self.assertEqual(row['package'], 'wholepact-native-host')
        self.assertEqual(row['command'], ['cargo', 'test', '--no-run'])
        self.assertEqual(row['exit_status'], -9)
        self.assertEqual(row['original_check'], 'client_deadline')
        self.assertTrue(row['diagnostic_unavailable'])
        self.assertTrue(row['client_cleanup_failed'])

    def test_unexpected_environment_refused_before_any_command(self):
        with mock.patch.object(S, 'checked') as checked, self.assertRaises(S.Failure):
            S.build_command('coordinator-production', ['cargo'], 'compile', {'GITHUB_TOKEN': 'private'})
        checked.assert_not_called()

    def test_command_cleanup_preserves_status_signal_and_original_failure(self):
        process, selector = mock.Mock(), mock.Mock()
        process.pid, process.returncode = 123, -9
        selector.get_map.return_value = {1: True}
        selector.select.return_value = [(mock.Mock(fileobj=process.stdout), None)]
        selector.close.side_effect = OSError('later cleanup error')
        with mock.patch.object(S.subprocess, 'Popen', return_value=process), \
             mock.patch.object(S.selectors, 'DefaultSelector', return_value=selector), \
             mock.patch.object(S.os, 'read', return_value=b'exceeds bound'), \
             mock.patch.object(S.os, 'killpg'), self.assertRaises(S.Failure) as caught:
            S.command(['inert'], 'compile', limit=1)
        self.assertEqual(caught.exception.check, 'output_limit')
        self.assertEqual(caught.exception.exit_status, -9)
        self.assertTrue(caught.exception.cleanup_failed)


class EncryptedBuildPrerequisites(unittest.TestCase):
    @staticmethod
    def files(prefix):
        for relative in ('lib/libsqlcipher.a', 'openssl/lib/libcrypto.a', 'include/sqlite3.h',
                         'include/sqlite3ext.h', 'lib/pkgconfig/sqlcipher.pc'):
            path = prefix / relative; path.parent.mkdir(parents=True, exist_ok=True); path.write_bytes(b'inert')
        (prefix / 'env.sh').write_text(f"export SQLCIPHER_LIB_DIR='{prefix}/lib'\n"
            f"export SQLCIPHER_INCLUDE_DIR='{prefix}/include'\nexport SQLCIPHER_STATIC=1\n"
            f"export PKG_CONFIG_ALL_STATIC=1\nexport WHOLEPACT_SQLCIPHER_PREFIX='{prefix}'\n")
        (prefix / 'build-versions.txt').write_text('4.19.0 community\nopenssl\nOpenSSL 3.5.9 29 Sep 2026\n')

    def build(self, root, mismatch=None):
        prefix = root / 'sqlcipher'
        def fake(name, args, stage, environment, **bounds):
            self.assertEqual(name, 'encrypted-storage-prerequisites')
            self.assertEqual(stage, 'prerequisites')
            if args[0] == 'bash':
                self.assertEqual(args, ['bash', 'scripts/build-encrypted-storage-deps.sh'])
                self.assertEqual(bounds, {'seconds': 1500, 'limit': 32 * 1024 * 1024})
                self.assertEqual(environment['WHOLEPACT_SQLCIPHER_PREFIX'], str(prefix))
                self.assertEqual(environment['WHOLEPACT_BUILD_JOBS'], '3')
                self.files(prefix)
                if mismatch == 'env': (prefix / 'env.sh').write_text('unexpected')
                if mismatch == 'version': (prefix / 'build-versions.txt').write_text('wrong')
                return b'not published on success'
            self.assertEqual(environment['SQLCIPHER_STATIC'], '1')
            self.assertEqual(environment['PKG_CONFIG_ALL_STATIC'], '1')
            if '--variable=prefix' in args:
                return b'/other\n' if mismatch == 'prefix' else (str(prefix) + '\n').encode()
            return b'-lsqlcipher\n' if mismatch == 'link' else (
                f'-L{prefix}/lib -lsqlcipher -L{prefix}/openssl/lib -lcrypto -ldl -lpthread -lm \n').encode()
        with mock.patch.object(S, 'build_command', side_effect=fake), \
             mock.patch.object(S.shutil, 'which', return_value='/fixed/tool'), \
             contextlib.redirect_stdout(io.StringIO()):
            return S.encrypted_build_environment(root, {'PATH': '/fixed', 'HOME': '/fresh'})

    def test_exact_builder_static_prefix_and_all_cargo_environment(self):
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            env = self.build(root)
            self.assertEqual(env['SQLCIPHER_LIB_DIR'], str(root / 'sqlcipher/lib'))
            self.assertEqual(env['SQLCIPHER_INCLUDE_DIR'], str(root / 'sqlcipher/include'))
            self.assertEqual(env['PKG_CONFIG_PATH'], str(root / 'sqlcipher/lib/pkgconfig'))
        source = (ROOT / 'ci-ui-supervisor.py').read_text()
        self.assertLess(source.index('env = encrypted_build_environment(root, env)'),
                        source.index('for name in I.ARTIFACT_FILES:'))
        self.assertIn('selected = dict(env)', source)
        self.assertIn("GIT_CONFIG_NOSYSTEM='1', GIT_CONFIG_GLOBAL='/dev/null', GIT_TERMINAL_PROMPT='0'", source)

    def test_prefix_link_env_and_version_drift_fail_closed(self):
        for mismatch, check in (('env', 'prerequisite_prefix'), ('version', 'prerequisite_versions'),
                                ('prefix', 'prerequisite_prefix'), ('link', 'prerequisite_link')):
            with tempfile.TemporaryDirectory() as directory, self.assertRaises(S.Failure) as caught:
                self.build(pathlib.Path(directory), mismatch)
            self.assertEqual(caught.exception.check, check)

    def test_exact_missing_tool_is_reported_before_silent_builder(self):
        output = io.StringIO()
        with tempfile.TemporaryDirectory() as directory, \
             mock.patch.object(S.shutil, 'which', side_effect=lambda tool, path: None if tool == 'tclsh' else '/fixed'), \
             mock.patch.object(S, 'build_command') as build, contextlib.redirect_stdout(output), \
             self.assertRaises(S.Failure) as caught:
            S.encrypted_build_environment(pathlib.Path(directory), {'PATH': '/fixed'})
        build.assert_not_called()
        self.assertEqual(caught.exception.check, 'prerequisite_tool')
        self.assertEqual(json.loads(output.getvalue().split(' ', 1)[1])['missing_tool'], 'tclsh')

    def test_builder_failure_has_same_bounded_diagnostic_not_runtime_logs(self):
        output = io.StringIO()
        failure = S.Failure('prerequisites', 'command_failed', b'make: compiler failed', 2)
        with mock.patch.object(S, 'checked', side_effect=failure), contextlib.redirect_stdout(output), \
             self.assertRaises(S.Failure):
            S.build_command('encrypted-storage-prerequisites', ['bash', 'scripts/build-encrypted-storage-deps.sh'],
                'prerequisites', {'PATH': '/fixed'})
        row = json.loads(output.getvalue().split(' ', 1)[1])
        self.assertEqual(row['package'], 'sqlcipher-4.19.0+openssl-3.5.9')
        self.assertEqual(row['exit_status'], 2)
        self.assertEqual(row['combined_stdout_stderr_tail'], 'make: compiler failed')
        source = (ROOT / 'ci-ui-supervisor.py').read_text()
        self.assertEqual(source.count('compile_failure(error,'), 2)  # definition and pre-credential wrapper only


class RecordsAndCleanup(unittest.TestCase):
    def test_streams_finite_failure_before_final_and_does_not_stream_pass(self):
        failure = dict(mode='fixture', stage='case', check='cancel')
        terminal = dict(outcome='error', first_failure=failure)
        stream = S.RuntimeRecords('fixture')
        output = io.StringIO()
        with mock.patch.object(S.P, 'validate_failure', side_effect=lambda value, mode: value, create=True), \
             mock.patch.object(S.P, 'validate_runtime_result', side_effect=lambda value, mode: value, create=True), \
             contextlib.redirect_stdout(output):
            stream(b'CI_UI_FAILURE ' + json.dumps(failure).encode())
            self.assertIn('CI_UI_FAILURE ', output.getvalue())
            before = output.getvalue()
            stream(json.dumps(terminal).encode())
            self.assertEqual(stream.finish(1), terminal)
            self.assertEqual(output.getvalue(), before)
        passed = S.RuntimeRecords('smoke')
        with mock.patch.object(S.P, 'validate_runtime_result', side_effect=lambda value, mode: value, create=True), \
             contextlib.redirect_stdout(output):
            passed(json.dumps({'outcome': 'passed', 'first_failure': None}).encode())
            passed.finish(0)
        self.assertNotIn('passed', output.getvalue())

    def test_duplicate_failure_records_and_terminal_status_are_rejected(self):
        stream = S.RuntimeRecords('smoke')
        with mock.patch.object(S.P, 'validate_failure', return_value={'check': 'fixed'}, create=True), \
             contextlib.redirect_stdout(io.StringIO()):
            stream(b'CI_UI_FAILURE {}')
            with self.assertRaises(S.Failure): stream(b'CI_UI_FAILURE {}')
        stream = S.RuntimeRecords('smoke'); stream.result = {'outcome': 'passed', 'first_failure': None}
        with self.assertRaises(S.Failure): stream.finish(1)

    def test_raw_unknown_records_never_echo(self):
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            with self.assertRaises(S.Failure): S.RuntimeRecords('smoke')(b'PRIVATE_SENTINEL')
        self.assertNotIn('PRIVATE_SENTINEL', output.getvalue())

    def test_client_timeout_still_removes_whole_container_and_retains_first(self):
        calls, output = [], io.StringIO()
        failure = {'mode': 'fixture', 'stage': 'case', 'check': 'fixed'}
        def attach(*args, **kwargs):
            kwargs['on_line'].first_failure = failure
            S.emit('FAILURE', failure)
            raise S.Failure('runtime', 'client_deadline')
        with mock.patch.object(S, 'names', return_value=[]), mock.patch.object(S, 'docker', return_value=b''), \
             mock.patch.object(S, 'inspect_isolation'), mock.patch.object(S, 'command', side_effect=attach), \
             mock.patch.object(S, 'docker_env', return_value={}), \
             mock.patch.object(S, 'remove_container', side_effect=lambda name, token: calls.append(name)), \
             contextlib.redirect_stdout(output):
            result, ok = S.run_case('fixture', 'sha256:' + 'a' * 64, 'token', 'b' * 40)
        self.assertFalse(ok); self.assertIsNone(result)
        self.assertEqual(calls, ['wp-ui-token-fixture'])
        self.assertEqual(output.getvalue().count('CI_UI_FAILURE '), 1)
        self.assertNotIn('client_deadline', output.getvalue())

    def test_uncertain_create_is_not_a_pass_after_empty_listing(self):
        with mock.patch.object(S, 'names', return_value=[]), \
             mock.patch.object(S, 'docker', side_effect=S.Failure('container', 'client_deadline')), \
             mock.patch.object(S, 'remove_container') as remove, contextlib.redirect_stdout(io.StringIO()):
            _, ok = S.run_case('smoke', 'sha256:' + 'a' * 64, 'token', 'b' * 40)
        self.assertFalse(ok); remove.assert_called_once_with('wp-ui-token-smoke', 'token')

    def test_listing_failure_still_attempts_force_removal_and_rechecks(self):
        calls = []
        with mock.patch.object(S, 'names', side_effect=[S.Failure('cleanup', 'client_deadline'), []]), \
             mock.patch.object(S, 'docker', side_effect=lambda args, *a, **k: calls.append(args) or b''):
            with self.assertRaises(S.Failure): S.remove_container('owned', 'token')
        self.assertIn(['kill', '--signal', 'KILL', 'owned'], calls)
        self.assertIn(['rm', '--force', '--volumes', 'owned'], calls)
        self.assertTrue(any('name=^/owned$' in call for call in calls))

    def test_cache_projection_requires_exact_zero_build_cache(self):
        self.assertTrue(S.cache_empty(b'{"Type":"Build Cache","TotalCount":0,"Size":"0B"}'))
        self.assertTrue(S.cache_empty(b'{"Type":"Build Cache","TotalCount":"0","Size":"0B"}'))
        for raw in (b'', b'PRIVATE_SENTINEL', b'{"Type":"Build Cache","TotalCount":1,"Size":"0B"}',
                    b'{"Type":"Build Cache","TotalCount":false,"Size":"0B"}',
                    b'{"Type":"Build Cache","TotalCount":0,"Size":"PRIVATE_SENTINEL"}'):
            self.assertFalse(S.cache_empty(raw))

    def test_cleanup_only_cannot_claim_lifecycle_pass(self):
        for clean in (True, False):
            output = io.StringIO()
            with tempfile.TemporaryDirectory() as directory, \
                 mock.patch.object(S, 'context', return_value=('a' * 40, 'token')), \
                 mock.patch.object(S, 'cleanup', return_value=clean), \
                 mock.patch.object(S.sys, 'argv', ['supervisor', 'cleanup']), \
                 mock.patch.dict(S.os.environ, {'RUNNER_TEMP': directory}), contextlib.redirect_stdout(output):
                self.assertEqual(S.main(), 0 if clean else 1)
            self.assertNotIn('CI_UI_RESULT ', output.getvalue())
            row = json.loads(output.getvalue().split(' ', 1)[1])
            self.assertEqual(row['lifecycle_result'], 'not_evaluated')
            self.assertEqual(row['cleanup_passed'], clean)

    def test_no_pass_before_all_cleanup(self):
        order = []
        result = dict(mode='smoke', outcome='passed', first_failure=None)
        def clean(*args): order.append('cleanup'); return True
        def emit(kind, value):
            if kind == 'CASE' or (kind == 'RESULT' and value['passed']): self.assertEqual(order, ['cleanup'])
        with tempfile.TemporaryDirectory() as directory, \
             mock.patch.object(S, 'context', return_value=('a' * 40, 'token')), \
             mock.patch.object(S, 'exact_source'), mock.patch.object(S, 'prepare_foundation_inputs', return_value=(pathlib.Path(directory), {})), \
             mock.patch.object(S, 'build_inputs'), mock.patch.object(S, 'build_image', return_value={'id': 'sha256:' + 'a' * 64}), \
             mock.patch.object(S, 'final_image', return_value='sha256:' + 'b' * 64), \
             mock.patch.object(S, 'docker', side_effect=[b'', b'', ('sha256:' + 'a' * 64).encode()]), \
             mock.patch.object(S, 'run_case', return_value=(result, True)), \
             mock.patch.object(S, 'cleanup', side_effect=clean), mock.patch.object(S, 'emit', side_effect=emit), \
             mock.patch.object(S.sys, 'argv', ['supervisor', 'run']), \
             mock.patch.dict(S.os.environ, {'RUNNER_TEMP': directory}):
            self.assertEqual(S.main(), 0)

    def test_image_failure_is_closed_and_value_free(self):
        output = io.StringIO()
        good = b'#8 2.0 {"schema_version":1,"phase":"install","code":"tool_exit","cleanup_failed":false}'
        with contextlib.redirect_stdout(output):
            self.assertTrue(S.image_failure(good))
            self.assertFalse(S.image_failure(good.replace(b'tool_exit', b'PRIVATE_SENTINEL')))
        self.assertNotIn('PRIVATE_SENTINEL', output.getvalue())


class FoundationOrdering(unittest.TestCase):
    def test_foundation_failure_stops_before_toolchain_or_cargo(self):
        output = io.StringIO()
        with tempfile.TemporaryDirectory() as directory, \
             mock.patch.object(S, 'context', return_value=('a' * 40, 'token')), \
             mock.patch.object(S, 'exact_source'), \
             mock.patch.object(S, 'prepare_foundation_inputs', return_value=(pathlib.Path(directory), {})), \
             mock.patch.object(S, 'build_image', side_effect=S.Failure('image', 'command_failed')), \
             mock.patch.object(S, 'build_inputs') as cargo, mock.patch.object(S, 'run_case') as runtime, \
             mock.patch.object(S, 'docker', return_value=b''), \
             mock.patch.object(S, 'cleanup', return_value=True), \
             mock.patch.object(S.sys, 'argv', ['supervisor', 'run']), \
             mock.patch.dict(S.os.environ, {'RUNNER_TEMP': directory}), contextlib.redirect_stdout(output):
            self.assertEqual(S.main(), 1)
        cargo.assert_not_called()
        runtime.assert_not_called()
        self.assertIn('"passed":false', output.getvalue())

    def test_existing_context_files_cannot_be_rewritten_after_foundation(self):
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            S.write_context_files(root, {'metadata.json': b'original'})
            S.write_context_files(root, {'metadata.json': b'original', 'new.json': b'final'})
            with self.assertRaises(S.Failure):
                S.write_context_files(root, {'metadata.json': b'changed'})
            self.assertEqual((root / 'metadata.json').read_bytes(), b'original')

    def test_only_same_job_foundation_can_finalize(self):
        foundation = {'id': 'sha256:' + 'a' * 64, 'layers': ('sha256:' + '1' * 64,)}
        final = {'id': 'sha256:' + 'b' * 64, 'layers': foundation['layers'] + ('sha256:' + '2' * 64,)}
        with mock.patch.object(S, 'image_descriptor', return_value=foundation), \
             mock.patch.object(S, 'build_image', return_value=final):
            self.assertEqual(S.final_image(None, 'final', 'foundation', 'token', 'source', foundation), final['id'])
        with mock.patch.object(S, 'image_descriptor', return_value=foundation), \
             mock.patch.object(S, 'build_image', return_value=dict(final, layers=('sha256:' + '3' * 64,))):
            with self.assertRaises(S.Failure):
                S.final_image(None, 'final', 'foundation', 'token', 'source', foundation)
        with mock.patch.object(S, 'image_descriptor', return_value=final), mock.patch.object(S, 'build_image') as build:
            with self.assertRaises(S.Failure):
                S.final_image(None, 'final', 'foundation', 'token', 'source', foundation)
            build.assert_not_called()

    def test_buildkit_error_without_installer_record_is_still_visible(self):
        error = S.Failure('image', 'command_failed', b'package install failed: missing dependency', exit_status=1)
        output = io.StringIO()
        with mock.patch.object(S, 'docker', side_effect=error), contextlib.redirect_stdout(output):
            with self.assertRaises(S.Failure):
                S.build_image('/context', 'foundation', 'tag', 'token', 'a' * 40, fresh=True)
        self.assertIn('package install failed: missing dependency', output.getvalue())
        self.assertIn('CI_UI_IMAGE_BUILD_FAILURE ', output.getvalue())
        self.assertIn('"exit_status":1', output.getvalue())

    def test_installer_tail_closed_identity_bounded_scrubbed(self):
        row = dict(schema_version=1, kind='pre_credential_tool', phase='install', code='tool_exit',
            tool='apt-get', command=['apt-get', '--no-download', 'install', '/ci-packages/fake.deb', 'fixed\tformat\n'],
            command_truncated=False, exit_status=100, output_bytes=45, tail_truncated=False,
            tail='missing dependency password=example', tool_cleanup_failed=False)
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            self.assertFalse(S.image_failure(b'#2 1.0 ' + json.dumps(row).encode()))
        self.assertIn('missing dependency', output.getvalue())
        self.assertNotIn('password=example', output.getvalue())
        self.assertIn('"exit_status":100', output.getvalue())
        row['tail'] = 'x' * 65537
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            S.image_failure(json.dumps(row).encode())
        self.assertEqual(output.getvalue(), '')


if __name__ == '__main__':
    unittest.main()
