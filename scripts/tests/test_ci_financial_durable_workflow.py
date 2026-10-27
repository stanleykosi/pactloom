"""Closed, additive durable V2 workflow checks; no build, process, or runtime."""
import ast
import hashlib
import pathlib
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[2]
WORKFLOW = ROOT / '.github/workflows/durable-native-linux.yml'
MODE = 'financial-durable-v2'
START = '      - name: Durable V2 recipe and projection gates (no build or fixture)\n'
END = '      - name: Fetch exact independent producer P and reviewed harness H without credentials\n'
OLD_SHA = '7b88ac6c175f67422011b43245c899e13ed9819b18416472eeb7438e3952b979'
BUILD = 'financial_durable_build'
RUN = 'financial_durable'


def new_steps(text):
    if text.count(START) != 1 or text.count(END) != 1:
        raise ValueError('step boundary')
    block = START + text.split(START, 1)[1].split(END, 1)[0]
    pieces = block.split('      - name: ')[1:]
    result = []
    for piece in pieces:
        rows = piece.splitlines()
        fields = {}
        for row in rows[1:]:
            if row.startswith('        ') and not row.startswith('         '):
                key, value = row.strip().split(':', 1)
                if key in fields:
                    raise ValueError('duplicate step field')
                fields[key] = value.strip()
        result.append((rows[0], fields, piece))
    return block, result


def condition(expression, *, mode, build_ok, ready, run_ok, success=True):
    values = {
        'steps.mode.outputs.gate': repr(mode),
        'steps.financial_durable_build.outcome': repr('success' if build_ok else 'failure'),
        'steps.financial_durable_build.outputs.artifact_bundle_ready': repr('true' if ready else 'false'),
        'steps.financial_durable.outcome': repr('success' if run_ok else 'failure'),
        'success()': repr(success), 'always()': 'True',
    }
    for name in sorted(values, key=len, reverse=True):
        expression = expression.replace(name, values[name])
    expression = expression.replace('&&', ' and ').replace('||', ' or ')
    parsed = ast.parse(expression, mode='eval')
    allowed = (ast.Expression, ast.BoolOp, ast.And, ast.Or, ast.Compare,
               ast.Eq, ast.NotEq, ast.Constant)
    if any(not isinstance(node, allowed) for node in ast.walk(parsed)):
        raise ValueError('unrecognized condition')
    return eval(compile(parsed, '<workflow condition>', 'eval'), {'__builtins__': {}}, {})


class DurableWorkflowTests(unittest.TestCase):
    def test_entire_legacy_workflow_is_exact_after_additive_inverse(self):
        text = WORKFLOW.read_bytes().decode('utf-8')
        block, _ = new_steps(text)
        restored = text.replace(block, '', 1)
        pairs = [
            ('|| "$mode" == financial-preparation-diagnostic || "$mode" == financial-durable-v2 ]]',
             '|| "$mode" == financial-preparation-diagnostic ]]'),
            ("&& steps.mode.outputs.gate != 'financial-preparation-diagnostic' && steps.mode.outputs.gate != 'financial-durable-v2'\n",
             "&& steps.mode.outputs.gate != 'financial-preparation-diagnostic'\n"),
        ]
        for new, old in pairs:
            self.assertEqual(restored.count(new), 1)
            restored = restored.replace(new, old, 1)
        self.assertEqual(hashlib.sha256(restored.encode()).hexdigest(), OLD_SHA)

    def test_closed_mode_and_order_do_not_cross_wire_old_profiles(self):
        self.assertEqual((ROOT / 'scripts/qualification-gate-mode').read_bytes(), b'financial-durable-v2\n')
        text = WORKFLOW.read_text()
        _, steps = new_steps(text)
        self.assertEqual(len(steps), 7)
        self.assertEqual([s[1].get('id') for s in steps], [None, BUILD, None, RUN, None, None, None])
        self.assertIn('scripts/ci-financial-launch-tests.py', steps[0][2])
        self.assertIn("unittest discover -s scripts/tests -p 'test*financial*.py'", steps[0][2])
        self.assertIn('scripts/ci-financial-supervisor.py build\n', steps[1][2])
        self.assertIn('scripts/ci-financial-supervisor.py run-built\n', steps[3][2])
        for _, fields, _ in steps:
            for mode in ('financial-ui', 'financial-semantic', 'financial-semantic-reuse', 'full', 'unknown'):
                self.assertFalse(condition(fields['if'], mode=mode, build_ok=True, ready=True, run_ok=True))
        origin = text.split('      - name: Minimal real production origin integration', 1)[1].split('      - name:', 1)[0]
        expression = next(row.strip()[4:] for row in origin.splitlines() if row.strip().startswith('if: '))
        self.assertFalse(condition(expression, mode=MODE, build_ok=True, ready=True, run_ok=True))

    def test_actual_runtime_condition_rejects_failed_build_and_job(self):
        _, steps = new_steps(WORKFLOW.read_text())
        expression = steps[3][1]['if']
        self.assertTrue(condition(expression, mode=MODE, build_ok=True, ready=True, run_ok=False))
        self.assertFalse(condition(expression, mode=MODE, build_ok=False, ready=True, run_ok=False))
        self.assertFalse(condition(expression, mode=MODE, build_ok=True, ready=True, run_ok=False, success=False))
        run = steps[3][2]
        self.assertIn('test "$FINANCIAL_BUILD_READY" = true\n', run)
        for field, output in [('READY', 'artifact_bundle_ready'), ('SHA256', 'artifact_bundle_sha256'), ('SIZE', 'artifact_bundle_size')]:
            self.assertIn('FINANCIAL_BUILD_' + field + ': ${{ steps.' + BUILD + '.outputs.' + output + ' }}', run)
        self.assertNotIn('steps.financial_build.', run)

    def test_upload_has_exact_same_job_custody_and_ready_gate(self):
        _, steps = new_steps(WORKFLOW.read_text())
        _, fields, upload = steps[2]
        self.assertEqual(fields['uses'], 'actions/upload-artifact@ea165f8d65b6e75b540449e92b4886f43607fa02 # v4.6.2')
        self.assertFalse(condition(fields['if'], mode=MODE, build_ok=True, ready=False, run_ok=False))
        self.assertFalse(condition(fields['if'], mode=MODE, build_ok=False, ready=True, run_ok=False))
        self.assertIn('wholepact-financial-build-${{ github.run_id }}-${{ github.run_attempt }}/build.tar', upload)
        for line in ('if-no-files-found: error', 'retention-days: 1', 'overwrite: false', 'include-hidden-files: false'):
            self.assertIn(line, upload)

    def test_cleanup_always_runs_and_summary_requires_actual_runtime_success(self):
        text = WORKFLOW.read_text()
        _, steps = new_steps(text)
        for _, fields, _ in steps[4:6]:
            self.assertTrue(condition(fields['if'], mode=MODE, build_ok=False, ready=False, run_ok=False, success=False))
        self.assertIn('scripts/ci-financial-supervisor.py cleanup', steps[4][2])
        self.assertIn('test ! -L "$directory"', steps[5][2])
        self.assertIn('rm -rf -- "$directory"', steps[5][2])
        self.assertFalse(condition(steps[6][1]['if'], mode=MODE, build_ok=True, ready=True, run_ok=False))
        summary = steps[6][2]
        self.assertIn('financial-durable-result-lifecycle-selective-v2', summary)
        self.assertIn('not standard fully optimized release or performance qualification', summary)
        self.assertIn('not the legacy coordinated', summary)
        self.assertIn('No intended-payee receipt, broadcast, chain inclusion', summary)
        self.assertIn('timeout-minutes: 210', text)
        self.assertIn('permissions:\n  contents: read\n  actions: read\n', text)

    def test_condition_model_fails_closed_on_unrecognized_bindings(self):
        with self.assertRaises(ValueError):
            condition("steps.other.outcome == 'success'", mode=MODE, build_ok=True, ready=True, run_ok=True)
        with self.assertRaises(ValueError):
            condition("dangerous()", mode=MODE, build_ok=True, ready=True, run_ok=True)


if __name__ == '__main__':
    unittest.main()
