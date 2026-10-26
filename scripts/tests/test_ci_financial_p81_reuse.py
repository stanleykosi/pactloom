"""Fixed-P81 boundary tests: fabricated inputs only; never run native artifacts.

The separate read-only evidence exercise uses preserved real API/ZIP bytes.
These portable tests do not claim hosted runtime or real acquisition coverage.
"""
import contextlib
import copy
import datetime
import hashlib
import importlib.util
import io
import json
import os
import pathlib
import signal
import subprocess
import tempfile
import tarfile
import unittest
from unittest.mock import patch

HERE = pathlib.Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('p81_boundary_under_test', HERE / 'ci-financial-p81-reuse.py')
R = importlib.util.module_from_spec(spec)
spec.loader.exec_module(R)


class CheckoutBoundaryTests(unittest.TestCase):
    """Real Git/blob/mode verification, not a mocked inventory success."""
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = pathlib.Path(self.temp.name) / 'source'
        self.root.mkdir()
        (self.root / 'Cargo.lock').write_bytes(b'version = 4\n')
        (self.root / 'tool').write_bytes(b'not an executable; test bytes only\n')
        (self.root / 'tool').chmod(0o755)
        (self.root / '.gitignore').write_bytes(b'__pycache__/\n')
        self.git('init', '-q')
        self.git('config', 'user.name', 'Boundary tests')
        self.git('config', 'user.email', 'boundary@example.invalid')
        self.git('add', '.')
        self.git('commit', '-qm', 'fabricated source fixture')
        self.commit = self.git('rev-parse', 'HEAD').strip().decode()

    def git(self, *args):
        return subprocess.check_output(['git', '-C', str(self.root), *args],
            env={'PATH': os.environ['PATH'], 'HOME': '/nonexistent',
                 'GIT_CONFIG_NOSYSTEM': '1', 'GIT_CONFIG_GLOBAL': '/dev/null',
                 'GIT_TERMINAL_PROMPT': '0'}, stderr=subprocess.DEVNULL)

    def verify(self):
        return R.inventory_checkout(self.root, self.commit)

    def test_real_checkout_binds_bytes_and_modes(self):
        tree, inventory = self.verify()
        self.assertEqual(tree, self.git('rev-parse', 'HEAD^{tree}').strip().decode())
        self.assertEqual(set(inventory), {'.gitignore', 'Cargo.lock', 'tool'})
        for name, mode in [('Cargo.lock', b'100644'), ('tool', b'100755')]:
            self.assertEqual(inventory[name], hashlib.sha256(mode + b'\0' + (self.root / name).read_bytes()).hexdigest())

    def test_wrong_commit_dirty_and_unexpected_source_are_denied(self):
        with self.assertRaises(R.Rejected):
            R.inventory_checkout(self.root, 'f' * 40)
        original = (self.root / 'Cargo.lock').read_bytes()
        (self.root / 'Cargo.lock').write_bytes(original + b'changed\n')
        with self.assertRaises(R.Rejected): self.verify()
        (self.root / 'Cargo.lock').write_bytes(original)
        (self.root / 'unexpected.py').write_bytes(b'not executed\n')
        with self.assertRaises(R.Rejected): self.verify()

    def test_ignored_stale_bytecode_is_denied(self):
        cache = self.root / '__pycache__'
        cache.mkdir()
        (cache / 'helper.pyc').write_bytes(b'fabricated stale bytecode')
        self.assertEqual(self.git('status', '--porcelain'), b'')
        with self.assertRaises(R.Rejected): self.verify()

    def test_exact_mode_is_checked_even_when_git_ignores_filemode(self):
        self.git('config', 'core.filemode', 'false')
        (self.root / 'Cargo.lock').chmod(0o755)
        self.assertEqual(self.git('status', '--porcelain'), b'')
        with self.assertRaises(R.Rejected): self.verify()

    def test_hardlinks_and_committed_symlinks_are_denied(self):
        original = self.root / 'Cargo.lock'
        outside = pathlib.Path(self.temp.name) / 'outside'
        outside.hardlink_to(original)
        with self.assertRaises(R.Rejected): self.verify()
        outside.unlink()
        original.unlink()
        original.symlink_to('tool')
        self.git('add', 'Cargo.lock')
        self.git('commit', '-qm', 'forbidden symlink fixture')
        self.commit = self.git('rev-parse', 'HEAD').strip().decode()
        with self.assertRaises(R.Rejected): self.verify()


    def test_added_test_pins_all_match_the_same_actual_tracked_blob(self):
        for name in R.H_ADDED:
            path = self.root / name
            path.parent.mkdir(parents=True, exist_ok=True)
            raw = b'# Fabricated inert added source; never executed.\n'
            path.write_bytes(raw)
            self.git('add', name)
            self.git('commit', '-qm', 'fabricated exact added test')
            commit = self.git('rev-parse', 'HEAD').strip().decode()
            pin = dict(mode='100644', sha256=R.sha(raw),
                       mode_content_sha256=R.sha(b'100644\0' + raw))
            with patch.object(R, 'H_ADDED', {name: pin}), \
                 patch.object(R, 'HARNESS', {**R.HARNESS, 'source': commit}), \
                 patch.object(R, 'tracked', wraps=R.tracked) as tracked:
                R.verify_added_harness(self.root)
                tracked.assert_called_once_with(self.root, commit, path)
                for key, value in [('mode', '100755'), ('sha256', 'f' * 64),
                                   ('mode_content_sha256', 'e' * 64)]:
                    with self.subTest(pin=key), patch.object(R, 'H_ADDED', {name: {**pin, key: value}}):
                        with self.assertRaises(R.Rejected): R.verify_added_harness(self.root)
                path.write_bytes(raw + b'# altered\n')
                with self.assertRaises(R.Rejected): R.verify_added_harness(self.root)
                path.write_bytes(raw)
                self.git('config', 'core.filemode', 'false')
                path.chmod(0o755)
                self.assertEqual(self.git('status', '--porcelain'), b'')
                with self.assertRaises(R.Rejected): R.verify_added_harness(self.root)
                path.chmod(0o644)
                R.verify_added_harness(self.root)


class FixedPolicyTests(unittest.TestCase):
    def test_only_exact_existing_and_added_reviewed_harness_deltas_are_accepted(self):
        producer = {name: 'a' * 64 for name in R.H_CHANGES}
        producer.update({'Cargo.lock': 'b' * 64, 'crates/native/src/lib.rs': 'c' * 64,
                         **{name: 'd' * 64 for name in R.A.BUILD_SCRIPTS}})
        harness = {**producer, **R.H_CHANGES, **{n:p['mode_content_sha256'] for n,p in R.H_ADDED.items()}}
        self.assertEqual(R.equivalent(producer, harness), R.H_CHANGES)
        for bad in ({**harness, 'Cargo.lock': 'f' * 64},
                    {**harness, R.A.BUILD_SCRIPTS[0]: 'f' * 64},
                    {**harness, 'crates/native/src/lib.rs': 'f' * 64},
                    {**harness, 'new.py': 'f' * 64}, producer,
                    *({**harness, name: 'f' * 64} for name in R.H_CHANGES)):
            with self.subTest(paths=set(bad) - set(producer)):
                with self.assertRaises(R.Rejected): R.equivalent(producer, bad)

    def test_credentials_never_enter_runtime_environment(self):
        with patch.dict(os.environ, {'PATH': '/usr/bin:/bin'}, clear=True):
            self.assertEqual(set(R.safe_environment()),
                {'PATH', 'HOME', 'GIT_CONFIG_NOSYSTEM', 'GIT_CONFIG_GLOBAL', 'GIT_TERMINAL_PROMPT'})
        for key in ('FINANCIAL_ARTIFACT_READ_TOKEN', 'GITHUB_TOKEN', 'ACTIONS_RUNTIME_TOKEN',
                    'PRIVATE_PASSWORD', 'A_SECRET', 'CREDENTIAL_FILE'):
            with patch.dict(os.environ, {'PATH': '/bin', key: 'fabricated'}, clear=True):
                with self.assertRaises(R.Rejected): R.safe_environment()

    def test_added_path_set_mode_hash_and_existing_overlap_are_exact(self):
        for name in R.H_ADDED:
            producer = {n: 'a' * 64 for n in R.H_CHANGES}
            producer.update({'Cargo.lock': 'b' * 64, 'crates/native/src/lib.rs': 'c' * 64})
            harness = {**producer, **R.H_CHANGES,
                       **{n: p['mode_content_sha256'] for n, p in R.H_ADDED.items()}}
            self.assertEqual(R.equivalent(producer, harness), R.H_CHANGES)
            for bad in (
                {n: v for n, v in harness.items() if n != name},
                {**harness, name: 'f' * 64},
                {**harness, name: R.sha(b'100755\0fabricated wrong-mode source')},
                {**harness, 'scripts/tests/another_test.py': 'd' * 64},
                {**harness, 'crates/native/src/added.rs': 'd' * 64},
                {n: v for n, v in harness.items() if n != 'Cargo.lock'},
            ):
                with self.subTest(paths=set(bad)), self.assertRaises(R.Rejected):
                    R.equivalent(producer, bad)
            # H_ADDED is an addition-only policy, never permission to replace P.
            overlap = {**producer, name: harness[name]}
            with self.assertRaises(R.Rejected) as caught: R.equivalent(overlap, harness)
            self.assertEqual(str(caught.exception), 'added_harness_overlap')

    def test_redirect_host_and_download_limits_fail_closed(self):
        good = 'https://results.blob.core.windows.net/a?sig=fabricated'
        self.assertEqual(R.redirect_target(good), good)
        for bad in ('http://results.blob.core.windows.net/a', 'https://api.github.com/a',
                    'https://results.blob.core.windows.net.evil.invalid/a',
                    'https://user@results.blob.core.windows.net/a',
                    'https://results.blob.core.windows.net:444/a',
                    good + '#fragment', 'file:///private'):
            with self.assertRaises(R.Rejected): R.redirect_target(bad)
        self.assertIsNone(R.NoRedirect().redirect_request(None, None, None, None, None, None))
        with self.assertRaises(R.Rejected): R.bounded_read(io.BytesIO(b'12345'), 4, float('inf'))
        with self.assertRaises(R.Rejected): R.bounded_read(io.BytesIO(b'1'), 4, 0)

    def test_existing_same_job_and_historical_policy_are_not_relabelled(self):
        self.assertEqual(R.PRODUCER['source'], '1fa2cec1dffd8672a107327de3046110d9fb4065')
        self.assertEqual(R.PINS['artifact_id'], 12632736595)
        self.assertEqual(R.A.MANIFEST_VERSION, 2)
        self.assertEqual(R.A.recipe(R.PROFILE)['build_recipe_version'], 3)
        self.assertEqual(set(R.H_CHANGES), {'.github/workflows/deadline-preflight.yml', 'scripts/ci-financial-flow.py', 'scripts/financial-runtime-reuse/test_integration.py', 'scripts/tests/test_ci_financial_close_preflight.py', 'scripts/tests/test_ci_financial_composition.py', 'scripts/tests/test_ci_financial_host_context.py', 'scripts/tests/test_ci_financial_observer.py'})
        self.assertEqual(set(R.H_ADDED), {'scripts/tests/test_ci_financial_host_entry_navigation.py', 'scripts/tests/test_ci_financial_initial_pair_navigation.py'})
        source = (HERE / 'ci-financial-p81-reuse.py').read_text()
        self.assertNotIn('S.build_inputs(', source)
        self.assertNotIn('S.same_job_inputs(', source)
        self.assertNotIn("'cargo'", source)
        historical = json.loads((HERE / 'financial-runtime-reuse/plan.json').read_text())
        self.assertEqual(historical['producer']['source'], '99501f5853a4516fc94a6361f39cb4373048f01f')
        for roots, launcher in [(('/P', '/P', '/L'), 'e' * 40),
                                (('/P', '/P/H', '/L'), 'e' * 40),
                                (('/P', '/H', '/L'), R.PRODUCER['source']),
                                (('/P', '/H', '/L'), R.HARNESS['source'])]:
            with self.assertRaises(R.Rejected): R.verify_sources(*roots, launcher)


class ParserBoundaryTests(unittest.TestCase):
    """Exercise the actual pinned strict parser with small non-executable bytes."""
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = pathlib.Path(self.temp.name)
        self.inputs = self.root / 'inputs'; self.inputs.mkdir()
        for name in R.A.NAMES:
            (self.inputs / name).write_bytes(b'\x7fELFfabricated; never executable ' + name.encode())
        self.bundle = self.root / 'bundle.tar'
        self.closure = {name: 'a' * 64 for name in R.A.BUILD_SCRIPTS}
        self.manifest = R.A.export_bundle(self.inputs, self.bundle, R.PRODUCER, self.closure, R.PROFILE)

    def test_recipe_cfg_profile_source_and_full_closure_are_exact(self):
        self.assertEqual(R.A.verify_bundle(self.bundle, R.PRODUCER, self.closure, R.PROFILE), self.manifest)
        for change in ('version', 'recipe_version', 'global_cfg', 'selector', 'rustflags', 'crypto', 'lock', 'source'):
            value = copy.deepcopy(self.manifest)
            if change == 'version': value['version'] = 1
            elif change == 'recipe_version': value['recipe']['build_recipe_version'] = 2
            elif change == 'global_cfg': value['recipe']['cfg_delivery']['global_financial_cfgs_permitted'] = True
            elif change == 'selector': value['recipe']['cfg_delivery']['effective_cfgs']['coordinator-observed'] = []
            elif change == 'rustflags': value['recipe']['observed_rustflags'] = '--cfg wholepact_financial_ci'
            elif change == 'crypto': value['recipe']['static_crypto'] = False
            elif change == 'lock': value['closure']['Cargo.lock'] = 'f' * 64
            else: value['identity']['source'] = R.HARNESS['source'] or 'f' * 40
            with self.subTest(change=change):
                with self.assertRaises(R.A.Rejected):
                    R.A.validate_manifest(value, R.PRODUCER, self.closure, R.PROFILE)

    def test_tar_mode_links_names_digest_truncation_padding_tail_are_denied(self):
        original = self.bundle.read_bytes()
        with tarfile.open(self.bundle, 'r:') as archive:
            members = archive.getmembers()
        binary = members[1]
        variants = {}
        for name, attr, value in [('mode', 'mode', 0o755), ('symlink', 'type', tarfile.SYMTYPE),
                                  ('hardlink', 'type', tarfile.LNKTYPE), ('path', 'name', '../escape'),
                                  ('order', 'name', members[2].name)]:
            member = copy.copy(binary); setattr(member, attr, value)
            if name in ('symlink', 'hardlink'): member.linkname = 'elsewhere'
            data = bytearray(original)
            data[binary.offset:binary.offset + 512] = member.tobuf(format=tarfile.USTAR_FORMAT)
            variants[name] = bytes(data)
        data = bytearray(original); data[binary.offset_data + 5] ^= 1; variants['digest'] = bytes(data)
        data = bytearray(original); data[binary.offset_data + binary.size] = 1; variants['padding'] = bytes(data)
        variants['truncated'] = original[:binary.offset_data + binary.size - 1]
        variants['tail'] = original + b'private-tail'
        self.bundle.chmod(0o600)
        for name, data in variants.items():
            self.bundle.write_bytes(data)
            with self.subTest(change=name):
                with self.assertRaises(R.A.Rejected):
                    R.A.verify_bundle(self.bundle, R.PRODUCER, self.closure, R.PROFILE)


class CleanupBoundaryTests(unittest.TestCase):
    """Inject failures only at side-effect boundaries; no Docker/native commands."""
    @classmethod
    def setUpClass(cls):
        path = HERE / 'ci-financial-supervisor.py'
        cls.S = R.module_bytes('p81_boundary_supervisor', path, path.read_bytes())

    def test_main_keeps_original_failure_when_trusted_cleanup_fails(self):
        for cleanup in (False, RuntimeError('cleanup failure')):
            first = R.Rejected('source failure')
            with tempfile.TemporaryDirectory() as tmp, contextlib.ExitStack() as stack:
                stack.enter_context(patch.dict(os.environ, {'PATH': '/usr/bin:/bin',
                    'RUNNER_TEMP': tmp, 'GITHUB_RUN_ID': '123', 'GITHUB_RUN_ATTEMPT': '1'}, clear=True))
                stack.enter_context(patch.object(R.sys, 'argv', ['adapter', 'verify', '/L', '/P', '/H']))
                stack.enter_context(patch.object(R, 'bootstrap', return_value=('e' * 40, 'owned', {})))
                stack.enter_context(patch.object(R, 'verify_sources', side_effect=first))
                cleanup_mock = stack.enter_context(patch.object(R, 'trusted_cleanup',
                    side_effect=cleanup if isinstance(cleanup, Exception) else None,
                    return_value=cleanup if not isinstance(cleanup, Exception) else None))
                with self.assertRaises(R.Rejected) as caught: R.main()
                self.assertIs(caught.exception, first)
                cleanup_mock.assert_called_once()

    def test_main_directory_removal_failure_does_not_skip_trusted_cleanup(self):
        first = R.Rejected('archive failure')
        with tempfile.TemporaryDirectory() as tmp, contextlib.ExitStack() as stack:
            staging = pathlib.Path(tmp) / 'wholepact-financial-p81-download-123-1'
            staging.mkdir(mode=0o700)
            for name in ('producer.zip', 'run.json', 'job.json', 'artifact.json'):
                (staging / name).write_bytes(b'fabricated')
            stack.enter_context(patch.dict(os.environ, {'PATH': '/usr/bin:/bin',
                'RUNNER_TEMP': tmp, 'GITHUB_RUN_ID': '123', 'GITHUB_RUN_ATTEMPT': '1'}, clear=True))
            stack.enter_context(patch.object(R.sys, 'argv', ['adapter', 'verify', '/L', '/P', '/H']))
            stack.enter_context(patch.object(R, 'bootstrap', return_value=('e' * 40, 'owned', {})))
            stack.enter_context(patch.object(R, 'verify_sources', return_value=({}, {}, {'source': 'e' * 40})))
            stack.enter_context(patch.object(R, 'verified_api', return_value={}))
            stack.enter_context(patch.object(R, 'verify_archive', side_effect=first))
            cleanup = stack.enter_context(patch.object(R, 'trusted_cleanup', return_value=True))
            stack.enter_context(patch.object(R.shutil, 'rmtree', side_effect=OSError('directory removal failure')))
            with self.assertRaises(R.Rejected) as caught: R.main()
            self.assertIs(caught.exception, first)
            cleanup.assert_called_once()

    def test_runtime_boundary_failures_cleanup_and_never_call_build(self):
        for failure in (None, 'root', 'source', 'package', 'context', 'pull', 'foundation', 'image', 'runtime', 'cleanup'):
            with self.subTest(boundary=failure), tempfile.TemporaryDirectory() as tmp, contextlib.ExitStack() as stack:
                root = pathlib.Path(tmp) / 'owned'; root.mkdir(mode=0o700)
                inputs = root / 'artifacts'; inputs.mkdir()
                if failure == 'root': (root / 'docker').mkdir()
                events = []; records = []
                def boundary(name, value=None):
                    def call(*args, **kwargs):
                        events.append(name)
                        if name == failure:
                            if name == 'cleanup': return False
                            raise self.S.Failure('image' if name in ('pull', 'foundation', 'image') else 'runtime', 'command_failed')
                        return value
                    return call
                stack.enter_context(patch.dict(os.environ, {'PATH': '/usr/bin:/bin'}, clear=True))
                # This portable L test has L's activation selector. Production
                # imports exact verified H, whose unchanged selector is semantic.
                stack.enter_context(patch.object(self.S.I, 'profile', return_value=R.PROFILE))
                for attribute, name, value in (
                    ('exact_source', 'source', None), ('package_preflight', 'package', None),
                    ('stage_image_context', 'context', root / 'context'), ('docker', 'pull', b''),
                    ('build_image', 'foundation', {}), ('final_image', 'image', 'runtime-image'),
                    ('run_case', 'runtime', ({}, True)), ('cleanup', 'cleanup', True)):
                    stack.enter_context(patch.object(self.S, attribute, side_effect=boundary(name, value)))
                stack.enter_context(patch.object(self.S, 'checked', side_effect=AssertionError('no native child permitted')))
                build = stack.enter_context(patch.object(self.S, 'build_inputs', side_effect=AssertionError('no compile permitted')))
                stack.enter_context(patch.object(self.S, 'emit', side_effect=lambda kind, data: records.append((kind, data))))
                status = R.runtime_owned(self.S, root, inputs, {'source': 'e' * 40}, 'owned')
                self.assertEqual(status, 0 if failure is None else 1)
                build.assert_not_called()
                self.assertIn('cleanup', events)
                self.assertFalse(root.exists())
                result = records[-1][1]
                self.assertEqual(result['native_producer'], R.PRODUCER)
                self.assertEqual(result['runtime_harness'], R.HARNESS)
                self.assertFalse(result['native_binaries_freshly_compiled'])
                self.assertFalse(result['synthetic_full_native_verified'])
                self.assertEqual(result['passed'], failure is None)


class CleanupChildTests(unittest.TestCase):
    """Only benign Python children; never Docker or any downloaded artifact."""
    def command(self, code):
        return [R.sys.executable, '-I', '-B', '-c', code]

    def test_bounded_child_success_exit_status_and_no_raw_output(self):
        with tempfile.TemporaryDirectory() as tmp, contextlib.redirect_stdout(io.StringIO()) as output:
            self.assertEqual(R.cleanup_process(self.command("print('private child text')"), tmp,
                {'PATH': '/usr/bin:/bin'}, seconds=5, limit=1024), 0)
            self.assertEqual(R.cleanup_process(self.command('raise SystemExit(7)'), tmp,
                {'PATH': '/usr/bin:/bin'}, seconds=5, limit=1024), 7)
        self.assertEqual(output.getvalue(), '')

    def test_hang_and_output_overflow_kill_and_reap_owned_child(self):
        cases = [('import time; time.sleep(10)', .1, 1024, 'cleanup_timeout'),
                 ("import os,time; os.write(1,b'x'*1048576); time.sleep(10)", 5, 1024, 'cleanup_output'),
                 ('import os,time; pid=os.fork(); time.sleep(10) if pid==0 else None',
                  .1, 1024, 'cleanup_timeout')]
        original_popen = subprocess.Popen; original_killpg = os.killpg
        for code, seconds, limit, reason in cases:
            children = []; kills = []
            def spawn(*args, **kwargs):
                process = original_popen(*args, **kwargs); children.append(process); return process
            def kill(pid, signum):
                kills.append((pid, signum)); return original_killpg(pid, signum)
            with self.subTest(reason=reason), tempfile.TemporaryDirectory() as tmp:
                try:
                    with patch.object(R.subprocess, 'Popen', side_effect=spawn), patch.object(R.os, 'killpg', side_effect=kill):
                        with self.assertRaises(R.Rejected) as caught:
                            R.cleanup_process(self.command(code), tmp, {'PATH': '/usr/bin:/bin'}, seconds=seconds, limit=limit)
                    self.assertEqual(caught.exception.args, (reason,))
                    self.assertEqual(len(children), 1)
                    self.assertIsNotNone(children[0].poll())
                    self.assertIn((children[0].pid, signal.SIGKILL), kills)
                finally:
                    for child in children:
                        if child.poll() is None: original_killpg(child.pid, signal.SIGKILL); child.wait(timeout=5)

    def test_selector_setup_failure_also_kills_and_reaps_started_child(self):
        original_popen = subprocess.Popen; children = []
        def spawn(*args, **kwargs):
            process = original_popen(*args, **kwargs); children.append(process); return process
        first = RuntimeError('fabricated selector setup failure')
        with tempfile.TemporaryDirectory() as tmp:
            try:
                with patch.object(R.subprocess, 'Popen', side_effect=spawn), \
                     patch.object(R.selectors, 'DefaultSelector', side_effect=first):
                    with self.assertRaises(RuntimeError) as caught:
                        R.cleanup_process(self.command('import time; time.sleep(10)'), tmp, {'PATH': '/usr/bin:/bin'})
                self.assertIs(caught.exception, first)
                self.assertEqual(len(children), 1)
                self.assertIsNotNone(children[0].poll())
            finally:
                for child in children:
                    if child.poll() is None: os.killpg(child.pid, signal.SIGKILL); child.wait(timeout=5)

    def test_exact_cleanup_annex_rejects_mutation_before_snapshot_or_spawn(self):
        sources = {name: b'financial-semantic\n' if name == 'qualification-gate-mode' else
                   (HERE / name).read_bytes() for name in R.CLEANUP_PINS}
        self.assertEqual(len(sources), 10)
        for name in ('ci-financial-contract.py', 'ci-financial-supervisor.py'):
            with self.subTest(name=name), \
                 patch.object(R.tempfile, 'mkdtemp', side_effect=AssertionError('no snapshot before verification')), \
                 patch.object(R, 'cleanup_process', side_effect=AssertionError('no child before verification')):
                with self.assertRaisesRegex(R.Rejected, '^cleanup_closure$'):
                    R.trusted_cleanup({**sources, name: sources[name] + b'# changed\n'})

    def test_pinned_cleanup_snapshot_and_child_environment_are_isolated(self):
        sources = {name: b'financial-semantic\n' if name == 'qualification-gate-mode' else
                   (HERE / name).read_bytes() for name in R.CLEANUP_PINS}
        for failure in (False, True):
            snapshots = []
            def child(args, cwd, env):
                snapshots.append(cwd)
                self.assertEqual(args[-1], 'cleanup')
                self.assertEqual(pathlib.Path(args[-2]), cwd / 'scripts/ci-financial-supervisor.py')
                self.assertNotIn('GITHUB_TOKEN', env)
                self.assertNotIn('UNRELATED', env)
                self.assertEqual({p.name for p in (cwd/'scripts').iterdir()}, set(R.CLEANUP_PINS))
                for name, expected in R.CLEANUP_PINS.items():
                    path = cwd/'scripts'/name
                    self.assertEqual(R.sha(path.read_bytes()), expected)
                    self.assertEqual(path.stat().st_mode & 0o777, 0o444)
                if failure: raise R.Rejected('fabricated cleanup child failure')
                return 0
            with tempfile.TemporaryDirectory() as tmp, contextlib.ExitStack() as stack:
                env = {name: 'test' for name in R.CI_KEYS}
                env.update(PATH='/usr/bin:/bin', RUNNER_TEMP=tmp, GITHUB_TOKEN='fabricated', UNRELATED='private')
                stack.enter_context(patch.dict(os.environ, env, clear=True))
                stack.enter_context(patch.object(R, 'cleanup_process', side_effect=child))
                stack.enter_context(contextlib.redirect_stdout(io.StringIO()))
                if failure:
                    with self.assertRaises(R.Rejected): R.trusted_cleanup(sources)
                else: self.assertTrue(R.trusted_cleanup(sources))
                self.assertEqual(len(snapshots), 1)
                self.assertFalse(snapshots[0].exists())


if __name__ == '__main__':
    unittest.main()
