"""Pure historical evidence/closure checks. No network, Docker or native effects."""
import copy
import importlib.util
from pathlib import Path
import unittest

SPEC = importlib.util.spec_from_file_location('prerequisite', Path(__file__).parents[1] / 'ci-ui-prerequisite.py')
M = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(M)

class PrerequisiteTests(unittest.TestCase):
    def test_exact_ci_diagnostic_delta_is_not_a_general_rust_exception(self):
        paths=set(M.CI_DIAGNOSTIC_HASHES)
        M.verify_paths(paths, diagnostic_hashes=M.CI_DIAGNOSTIC_HASHES)
        for hashes in (None, {}, {**M.CI_DIAGNOSTIC_HASHES, next(iter(paths)): ('0'*64,'0'*64)}):
            with self.assertRaisesRegex(ValueError,'ci_diagnostic_delta'):
                M.verify_paths(paths, diagnostic_hashes=hashes)
        with self.assertRaisesRegex(ValueError,'ci_diagnostic_delta'):
            M.verify_paths(paths-{next(iter(paths))}, diagnostic_hashes=M.CI_DIAGNOSTIC_HASHES)
        with self.assertRaisesRegex(ValueError,'source_closure_changed'):
            M.verify_paths(paths|{'crates/wholepact-authority/src/lib.rs'}, diagnostic_hashes=M.CI_DIAGNOSTIC_HASHES)
        self.assertFalse(paths & M.ALLOWED)

    def record(self):
        return {'jobs': [{'id': M.JOB, 'run_id': M.RUN, 'run_attempt': 1,
                         'head_sha': M.BASE, 'head_branch': 'qualification/durable-proposal-v1',
                         'status': 'completed', 'conclusion': 'failure',
                         'steps': [{'name': n, 'status': 'completed', 'conclusion': 'success'} for n in M.STEPS]}]}

    def test_exact_failed_run_successful_prerequisite(self):
        M.verify_jobs(self.record())

    def test_missing_duplicate_or_wrong_identity(self):
        for key, value in [('id', 0), ('run_id', 0), ('run_attempt', 2), ('head_sha', '0'*40),
                           ('head_branch', 'main'), ('status', 'in_progress'), ('conclusion', 'success')]:
            r=self.record(); r['jobs'][0][key]=value
            with self.subTest(key=key), self.assertRaises(ValueError): M.verify_jobs(r)
        for r in ({'jobs': []}, {'jobs': self.record()['jobs']*2}):
            with self.assertRaises(ValueError): M.verify_jobs(r)

    def test_step_failure_missing_or_duplicate_refuses(self):
        for i in range(2):
            for key, value in [('status', 'in_progress'), ('conclusion', 'failure'), ('conclusion', 'skipped')]:
                r=self.record(); r['jobs'][0]['steps'][i][key]=value
                with self.assertRaises(ValueError): M.verify_jobs(r)
            r=self.record(); r['jobs'][0]['steps'].pop(i)
            with self.assertRaises(ValueError): M.verify_jobs(r)
            r=self.record(); r['jobs'][0]['steps'].append(copy.deepcopy(r['jobs'][0]['steps'][i]))
            with self.assertRaises(ValueError): M.verify_jobs(r)

    def test_diff_cannot_hide_old_path_as_rename(self):
        source = Path(M.__file__).read_text()
        self.assertIn('git("diff", "--no-renames", "--name-only", "-z", BASE, "HEAD")', source)

    def test_setup_diagnostics_only_add_exact_nonbootstrap_paths(self):
        additions = {'scripts/ci-ui-setup-wrapper.py', 'scripts/ci-ui-output.py',
                     'scripts/ci-ui-container.py', 'scripts/tests/test_ci_ui_setup.py'}
        self.assertTrue(additions <= M.ALLOWED)
        self.assertEqual(len(M.ALLOWED), 23)
        M.verify_paths(additions)
        for path in ('scripts/ci-bootstrap-output.py', 'scripts/build-encrypted-storage-deps.sh',
                     'crates/wholepact-native-host/src/lib.rs'):
            with self.assertRaises(ValueError): M.verify_paths(additions | {path})

    def test_export_helpers_are_not_a_rust_allowlist(self):
        M.verify_paths(['scripts/ci-ui-artifacts.py', 'scripts/tests/test_ci_ui_artifacts.py'])
        self.assertNotIn(M.FIXTURE, M.ALLOWED)
        for pair in (None, (M.FIXTURE_BEFORE, '0'*64), ('0'*64, M.FIXTURE_AFTER),
                     (M.FIXTURE_AFTER, M.FIXTURE_BEFORE)):
            with self.assertRaises(ValueError): M.verify_paths([M.FIXTURE], pair)
        M.verify_paths([M.FIXTURE], (M.FIXTURE_BEFORE, M.FIXTURE_AFTER))
        with self.assertRaises(ValueError):
            M.verify_paths([M.FIXTURE, 'crates/wholepact-native-host/src/lib.rs'],
                           (M.FIXTURE_BEFORE, M.FIXTURE_AFTER))

    def test_inactive_runner_paths_remain_ci_only(self):
        M.verify_paths(["scripts/ci-ui-reuse.py", "scripts/tests/test_ci_ui_reuse.py",
                        "scripts/ci-ui-reuse-runner.py", "scripts/tests/test_ci_ui_reuse_runner.py",
                        "scripts/ci-ui-reuse-pin.json", "scripts/ci-ui-linux.sh"])
        for path in ("scripts/ci-ui-reuse-other.py", "crates/wholepact-authority/Cargo.toml",
                     "crates/wholepact-financial-coordinator-origin/src/ci.rs"):
            with self.assertRaises(ValueError): M.verify_paths([path])

    def test_ci75_container_test_is_exact_nonbootstrap_exception(self):
        M.verify_paths(["scripts/tests/test_ci_ui_container.py"])
        for path in ("scripts/tests/test_ci_bootstrap_container.py",
                     "scripts/ci-bootstrap-container.py", "scripts/tests/new.py"):
            with self.assertRaisesRegex(ValueError, "source_closure_changed"):
                M.verify_paths([path])

    def test_public_failure_codes_never_include_exception_payload(self):
        for code in M.FAILURE_CODES:
            self.assertEqual(M.failure_code(ValueError(code)), code)
        for error in (ValueError("private payload"), RuntimeError("private payload"),
                      ValueError("source_closure_changed", "private payload")):
            self.assertEqual(M.failure_code(error), "evidence_or_internal")
        self.assertEqual(M.failure_code(M.subprocess.TimeoutExpired("private", 1)), "git_timeout")
        self.assertEqual(M.failure_code(M.subprocess.CalledProcessError(1, "private")), "git_command")

    def test_main_reports_closure_reason_before_network(self):
        from unittest.mock import patch
        import contextlib, io
        outputs = [M.TREE.encode(), b"", b"scripts/ci-bootstrap-container.py\0"]
        captured = io.StringIO()
        with patch.object(M, 'git', side_effect=outputs), patch.object(M.urllib.request, 'urlopen') as network:
            with contextlib.redirect_stdout(captured):
                self.assertEqual(M.main(), 1)
            network.assert_not_called()
        self.assertEqual(captured.getvalue(), "CI_UI_PREREQUISITE historical_reuse=false verified=false code=source_closure_changed\n")

    def test_only_gateway_transients_receive_one_readonly_retry(self):
        from unittest.mock import patch
        import io, json
        for status in (502,503,504):
            error=M.urllib.error.HTTPError('https://private',status,'private',{},io.BytesIO(b'private'))
            request=M.urllib.request.Request('https://api.github.com/exact')
            with patch.object(M.urllib.request,'urlopen',side_effect=[error,io.BytesIO(json.dumps(self.record()).encode())]) as get, patch.object(M.time,'sleep') as sleep:
                M.verify_jobs(M.fetch_evidence(request))
            self.assertEqual(get.call_count,2)
            self.assertTrue(all(call.args==(request,) and call.kwargs=={'timeout':20} for call in get.call_args_list))
            self.assertEqual(request.get_method(),'GET')
            self.assertNotIn('Authorization',request.headers)
            sleep.assert_called_once_with(0.25)

    def test_auth_missing_rate_limit_and_repeated_transient_fail_closed(self):
        from unittest.mock import patch
        import io
        for status in (401,403,404,429,500,502):
            errors=[M.urllib.error.HTTPError('https://private',status,'private',{},io.BytesIO()) for _ in range(2)]
            with patch.object(M.urllib.request,'urlopen',side_effect=errors) as get, patch.object(M.time,'sleep'):
                with self.assertRaises(M.urllib.error.HTTPError): M.fetch_evidence(M.urllib.request.Request('https://api.github.com/exact'))
            self.assertEqual(get.call_count,2 if status==502 else 1)

    def test_parse_size_network_and_timeout_are_never_retried(self):
        from unittest.mock import patch
        import io
        for response in (io.BytesIO(b'private invalid JSON'),io.BytesIO(b'x'*262145),
                         M.urllib.error.URLError('private'),TimeoutError('private')):
            with patch.object(M.urllib.request,'urlopen',side_effect=[response] if isinstance(response,Exception) else None,return_value=response) as get, patch.object(M.time,'sleep') as sleep:
                with self.assertRaises(Exception): M.fetch_evidence(M.urllib.request.Request('https://api.github.com/exact'))
            self.assertEqual(get.call_count,1);sleep.assert_not_called()

    def test_closed_http_diagnostic_contains_no_exception_body_or_url(self):
        import io, contextlib
        from unittest.mock import patch
        error=M.urllib.error.HTTPError('https://private-path',403,'private-message',{'private':'header'},io.BytesIO(b'private body'))
        output=io.StringIO()
        with patch.object(M,'git',side_effect=[M.TREE.encode(),b'',b'']),patch.object(M.urllib.request,'urlopen',side_effect=error),contextlib.redirect_stdout(output):
            self.assertEqual(M.main(),1)
        self.assertEqual(output.getvalue(),'CI_UI_PREREQUISITE historical_reuse=false verified=false code=evidence_http http_status=403\n')
        self.assertNotIn('private',output.getvalue())
        self.assertEqual(M.failure_code(M.urllib.error.URLError('private')),'evidence_network')
        self.assertEqual(M.failure_code(M.urllib.error.URLError(TimeoutError('private'))),'evidence_timeout')
        self.assertEqual(M.failure_code(M.json.JSONDecodeError('private','private',0)),'evidence_json')

    def test_complete_nonallowlisted_tree_is_frozen(self):
        M.verify_paths(M.ALLOWED)
        for path in ('Cargo.lock', 'Cargo.toml', 'rust-toolchain.toml', 'scripts/ci-bootstrap-linux.sh',
                     'scripts/ci-bootstrap-supervisor.py', 'scripts/qualification-gate-mode',
                     'crates/wholepact-financial-coordinator-origin/src/bootstrap.rs', 'new.rs'):
            with self.subTest(path=path), self.assertRaises(ValueError): M.verify_paths([path])

if __name__ == '__main__': unittest.main()
