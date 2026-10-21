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
        self.assertLess(source.index('shutil.copyfile(artifact'), source.index('pins[name] = pin(inputs / name)'))
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

    def test_staging_cause_is_closed_and_cleanup_separate(self):
        error = S.Failure('packages', 'staging_rejected')
        error.cause, error.cleanup_failed = 'download_digest', True
        value = S.failure_record(error)
        self.assertEqual(value['cause'], 'download_digest')
        self.assertTrue(value['client_or_staging_cleanup_failed'])
        error.cause = 'PRIVATE_SENTINEL'
        self.assertNotIn('PRIVATE_SENTINEL', json.dumps(S.failure_record(error)))


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
             mock.patch.object(S, 'exact_source'), mock.patch.object(S, 'build_inputs', return_value=(pathlib.Path(directory), {})), \
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


if __name__ == '__main__':
    unittest.main()
