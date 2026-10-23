"""Concrete launch wiring checks. No network, product or Docker execution."""
import hashlib
import json
import pathlib
import unittest
from test_setup import L
HERE=pathlib.Path(__file__).resolve().parent
ROOT=HERE.parents[1]
class IntegrationTests(unittest.TestCase):
 def test_concrete_plan_pins_and_exact_delta(self):
  plan=L.validate_plan(json.loads((HERE/'plan.json').read_text()))
  self.assertEqual(plan['harness']['source'],'ca9272d8786c5152c538effdcc7ed10144ad0bac')
  self.assertEqual(plan['harness']['source_tree'],'c343ba9fa73fd6a5a77a8922552964a638578014')
  self.assertEqual(plan['artifact_pins']['artifact_id'],12466205927)
  self.assertEqual(set(plan['reviewed_runtime_changes']),{'scripts/ci-financial-fixture.py','scripts/ci-financial-flow.py','scripts/tests/test_ci_financial_observer.py'})
  self.assertNotIn('launcher',plan)
  self.assertEqual(plan['policy'],L.V.POLICY)
  self.assertEqual(plan['qualification_profile'],L.V.QUALIFICATION_PROFILE)
  self.assertEqual(plan['version'],4)
  self.assertNotIn('transition_compatibility',plan)
  self.assertNotIn('diagnostic_compatibility',plan)
  for path,pin in plan['reviewed_runtime_changes'].items():
   data=(ROOT/path).read_bytes()
   self.assertEqual(hashlib.sha256(b'100644\0'+data).hexdigest(),pin)
 def test_gate_and_context_do_not_request_native_rebuild(self):
  self.assertEqual((ROOT/'scripts/qualification-gate-mode').read_bytes(),b'financial-semantic-reuse\n')
  workflow=(ROOT/'.github/workflows/durable-native-linux.yml').read_text()
  self.assertIn("steps.mode.outputs.gate != 'financial-ui' && steps.mode.outputs.gate != 'financial-semantic' && steps.mode.outputs.gate != 'financial-semantic-reuse'",workflow)
  self.assertIn("if: steps.mode.outputs.gate == 'financial-ui'",workflow)
  self.assertIn('branches: [qualification/durable-proposal-v1]',workflow)
  self.assertNotIn('financial-runtime-reuse-04',workflow)
 def test_runtime_and_cleanup_have_no_acquisition_token(self):
  workflow=(ROOT/'.github/workflows/durable-native-linux.yml').read_text()
  self.assertEqual(workflow.count('FINANCIAL_ARTIFACT_READ_TOKEN:'),1)
  runtime=workflow.split('      - name: Actual synthetic financial runtime',1)[1]
  self.assertNotIn('github.token',runtime)
  self.assertIn('env -i PATH=',runtime)
  self.assertIn("if: always() && steps.mode.outputs.gate == 'financial-semantic-reuse'",runtime)
  self.assertIn('launch_adapter.py" cleanup "${GITHUB_WORKSPACE}/source"',runtime)
  self.assertNotIn('acquire_archive.py',workflow)
 def test_smoke_is_original_cleanup_not_native_execution(self):
  workflow=(ROOT/'.github/workflows/durable-native-linux.yml').read_text()
  smoke=workflow.split('      - name: Pre-runtime trusted cleanup smoke',1)[1].split('      - name:',1)[0]
  self.assertIn('launch_adapter.py" cleanup',smoke)
  self.assertNotIn(' smoke ',smoke)
  self.assertNotIn(' run ',smoke)
  self.assertNotIn('pristine-setup',smoke)
if __name__=='__main__':unittest.main()
