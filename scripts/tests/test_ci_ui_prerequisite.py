"""Pure historical evidence/closure checks. No network, Docker or native effects."""
import copy
import importlib.util
from pathlib import Path
import unittest

SPEC = importlib.util.spec_from_file_location('prerequisite', Path(__file__).parents[1] / 'ci-ui-prerequisite.py')
M = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(M)

class PrerequisiteTests(unittest.TestCase):
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
        self.assertEqual(len(M.ALLOWED), 11)
        M.verify_paths(additions)
        for path in ('scripts/ci-bootstrap-output.py', 'scripts/build-encrypted-storage-deps.sh',
                     'crates/wholepact-native-host/src/lib.rs'):
            with self.assertRaises(ValueError): M.verify_paths(additions | {path})

    def test_complete_nonallowlisted_tree_is_frozen(self):
        M.verify_paths(M.ALLOWED)
        for path in ('Cargo.lock', 'Cargo.toml', 'rust-toolchain.toml', 'scripts/ci-bootstrap-linux.sh',
                     'scripts/ci-bootstrap-supervisor.py', 'scripts/qualification-gate-mode',
                     'crates/wholepact-financial-coordinator-origin/src/bootstrap.rs', 'new.rs'):
            with self.subTest(path=path), self.assertRaises(ValueError): M.verify_paths([path])

if __name__ == '__main__': unittest.main()
