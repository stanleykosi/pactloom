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
  self.assertEqual(plan['harness']['source'],'99f26c7490186f0e8034c2d32c24754799a96d7a')
  self.assertEqual(plan['harness']['source_tree'],'57a1b5fe78534cfad517dbe71f60c89e0930804c')
  self.assertEqual(plan['artifact_pins']['artifact_id'],12458757246)
  self.assertEqual(set(plan['reviewed_runtime_changes']),{'scripts/tests/test_ci_financial_observer.py', 'scripts/ci-financial-flow.py'})
  self.assertNotIn('launcher',plan)
  self.assertEqual(plan['policy'],L.V.POLICY)
  self.assertEqual(plan['qualification_profile'],L.V.QUALIFICATION_PROFILE)
  self.assertEqual(plan['version'],3)
  self.assertEqual(plan['transition_compatibility'],L.V.TRANSITION_COMPATIBILITY)
  annex=plan['transition_compatibility']
  self.assertEqual(hashlib.sha256(b'100644\0'+(ROOT/annex['path']).read_bytes()).hexdigest(),annex['harness_mode_sha256'])
  for role,base in [('harness',ROOT),('producer',ROOT.parent/'P')]:
   blob=(base/annex['path']).read_bytes()
   self.assertEqual(hashlib.sha256(blob).hexdigest(),annex[role+'_sha256'])
   self.assertEqual(hashlib.sha1(b'blob '+str(len(blob)).encode()+b'\0'+blob).hexdigest(),annex[role+'_git_blob'])
   self.assertEqual(oct((base/annex['path']).stat().st_mode&0o777),'0o644')
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
