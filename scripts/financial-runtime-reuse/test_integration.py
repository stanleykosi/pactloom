"""Private unbound scaffold wiring; never activate or execute native artifacts."""
import hashlib,json,pathlib,unittest
from test_setup import L,TRUSTED
HERE=pathlib.Path(__file__).resolve().parent
ROOT=HERE.parents[1]
class IntegrationTests(unittest.TestCase):
 def test_concrete_p40_h41_v2_plan(self):
  p=json.loads((HERE/'plan.json').read_text());self.assertEqual(p['harness'],{'repository': 'stanleykosi/pactloom', 'source': '3fc27434f7ee5d2af5f71c9d9010b982bedf74dd', 'source_tree': '2f70ddbbf2e740ed3001a117a30f479429fd125a'})
  self.assertEqual(L.validate_plan(p),p)
  self.assertEqual(p['producer'],L.V.PRODUCER);self.assertEqual(p['artifact_pins'],L.V.ARTIFACT_PINS);self.assertEqual(p['api_pins'],L.V.API_PINS)
  self.assertEqual(p['manifest_version'],2);self.assertEqual(p['build_recipe_version'],2);self.assertEqual(p['version'],6)
  self.assertEqual(p['artifact_pins']['artifact_id'],12491706804)
  self.assertEqual(p['reviewed_runtime_changes'],{'scripts/ci-financial-flow.py': 'fae619497e7fc66f9195169565c04ea7150bc74684ae99d221c2f8555c34ea0a', 'scripts/tests/test_ci_financial_observer.py': '6371af4423436b82c7ee654bb92798b6aa6cf96ea5818a70de1acd0155b354a3'})
 def test_p40_parser_and_cleanup_exact_current_sources(self):
  self.assertEqual(hashlib.sha256((HERE/'producer_artifacts.py').read_bytes()).hexdigest(),'c6d12ee5a132083ee97f5aee7fcda3b3dc270a794b90d3d65e18b271c3426682')
  self.assertEqual(hashlib.sha256((ROOT/'scripts/ci-financial-artifacts.py').read_bytes()).hexdigest(),'f31041a577f3fa0dc65f5880ac0a77d8fd145e53d4d576524ede3e2adbec29ce')
  for path,pin in L.CLEANUP_PINS.items():
   data=(HERE/path).read_bytes();self.assertEqual(hashlib.sha256(data).hexdigest(),pin)
   relative=str(pathlib.Path(path).relative_to('cleanup_snapshot'))
   # Historical P40 cleanup remains pinned; current comparison uses exact reviewed P70 bytes.
   fresh_changes={'scripts/ci-financial-container.py': '83fa5dfa4f9db25bd7a769287e3aa32a199f73865fc1dbabeb93d762a7424b1c', 'scripts/ci-financial-contract.py': 'e78bc21fe26082bc1012c538a6dd24c78f1bf6ac75ff16b2374dfe1237079d87', 'scripts/ci-financial-external-output.py': '109dded70c7d7eca3160dd305601b3f5c9f31e24c8f0e6bb3c5161f8652c5587', 'scripts/ci-financial-observer.py': '0ae5a98b2bfa4358e2df9c183a5066911751eae48a26b5f968e9457ef002c7da', 'scripts/ci-financial-scenario.py': '691c58bea53ddb22ed645cc8462227ca4081487c154ed2e4c956580efe5423c6', 'scripts/ci-financial-supervisor.py': '12504501acd3ceff8fe0a89273f0da2be321c1e760e7e091fef8f7c5734050e4', 'scripts/tests/test_ci_financial_observer.py': '467a6001e151ca1bfb215e3c22d5fd480667cff27b77a3faa1cb683ca86577a6', 'scripts/ci-financial-artifacts.py': 'f31041a577f3fa0dc65f5880ac0a77d8fd145e53d4d576524ede3e2adbec29ce'}
   if relative in fresh_changes:self.assertEqual(hashlib.sha256((ROOT/relative).read_bytes()).hexdigest(),fresh_changes[relative])
   else:self.assertEqual(data,b'financial-semantic\n' if path.endswith('/qualification-gate-mode') else (ROOT/relative).read_bytes())
 def test_cleanup_dependency_closure_imports_without_execution(self):
  s=TRUSTED.module('cleanup_closure_probe',L.HERE/'cleanup_snapshot/scripts/ci-financial-supervisor.py')
  self.assertEqual(s.A.MANIFEST_VERSION,2);self.assertEqual(s.A.recipe(L.V.QUALIFICATION_PROFILE),L.V.A.recipe(L.V.QUALIFICATION_PROFILE))
 def test_mandatory_tests_and_cleanup_remain_wired(self):
  text=(HERE/'launch_adapter.py').read_text()
  self.assertIn("'scripts/ci-financial-launch-tests.py'",text);self.assertIn("'test*financial*.py'",text)
  self.assertIn('clean=S.cleanup(token,tag)',text);self.assertIn('clean=trusted_cleanup(trusted)',text)
  self.assertNotIn('S.build_inputs(',text);self.assertNotIn("'cargo'",text)
 def test_exact_private_workflow_wiring(self):
  self.assertEqual((ROOT/'scripts/qualification-gate-mode').read_bytes(),b'financial-semantic\n')
  w=(ROOT/'.github/workflows/durable-native-linux.yml').read_text()
  titles=('Financial recipe and projection gates (no build or fixture)','Fresh exact-source financial build (no runtime fixture)','Preserve exact credential-free compiled financial bundle','Financial image and native runtime (verified same-job fresh bundle)')
  positions=[w.index('      - name: '+title) for title in titles]
  self.assertEqual(positions,sorted(positions))
  blocks=[w.split('      - name: '+title,1)[1].split('      - name:',1)[0] for title in titles]
  for block in blocks:self.assertIn("steps.mode.outputs.gate == 'financial-semantic'",block)
  self.assertIn('scripts/ci-financial-launch-tests.py',blocks[0]);self.assertIn("-p 'test*financial*.py'",blocks[0])
  self.assertIn('scripts/ci-financial-supervisor.py build',blocks[1])
  self.assertIn("steps.financial_build.outcome == 'success'",blocks[2]);self.assertIn("steps.financial_build.outputs.artifact_bundle_ready == 'true'",blocks[2])
  self.assertIn("steps.financial_build.outcome == 'success'",blocks[3]);self.assertIn('test "$FINANCIAL_BUILD_READY" = true',blocks[3])
  self.assertIn('scripts/ci-financial-supervisor.py run-built',blocks[3])
  self.assertIn('steps.financial_build.outputs.artifact_bundle_sha256',blocks[3]);self.assertIn('steps.financial_build.outputs.artifact_bundle_size',blocks[3])
  for title in ('Fetch exact independent producer P and reviewed harness H without credentials','Acquire exact producer bundle with isolated read token','Actual synthetic financial runtime using verified producer binaries (not a fresh build)','Preserved P35 preparation, owned admissions and process-death reopen diagnostic (NOT full flow)'):
   block=w.split('      - name: '+title,1)[1].split('      - name:',1)[0]
   condition=next(line for line in block.splitlines() if line.strip().startswith('if:'))
   self.assertNotIn("gate == 'financial-semantic'",condition)
  cleanup=w.split('      - name: Verify financial containers, temporary images and build cache removed',1)[1].split('      - name:',1)[0]
  self.assertIn("always() &&",cleanup);self.assertIn("gate == 'financial-semantic'",cleanup)
  self.assertIn('scripts/ci-financial-supervisor.py cleanup',cleanup)
if __name__=='__main__':unittest.main()

class CleanupProfileTests(unittest.TestCase):
 def test_current_p40_cleanup_main_has_pinned_profile_input(self):
  from unittest.mock import patch
  import tempfile,os
  s=TRUSTED.module('cleanup_main_probe',L.HERE/'cleanup_snapshot/scripts/ci-financial-supervisor.py')
  with tempfile.TemporaryDirectory() as tmp,patch.dict(os.environ,{'RUNNER_TEMP':tmp}),patch.object(s,'context',return_value=('a'*40,'token')),patch.object(s.sys,'argv',['supervisor','cleanup']),patch.object(s,'cleanup',return_value=True) as cleanup,patch.object(s,'emit'):
   self.assertEqual(s.main(),0);cleanup.assert_called_once()

class IdenticalSourceTests(unittest.TestCase):
 def test_zero_delta_only_for_exact_producer_identity(self):
  p=json.loads((HERE/'plan.json').read_text());p['harness']={k:L.V.PRODUCER[k] for k in ('repository','source','source_tree')};p['reviewed_runtime_changes']={};L.validate_plan(p)
  import copy
  for key in ('source','source_tree','repository'):
   changed=copy.deepcopy(p);changed['harness'][key]='f'*40
   with self.assertRaises(L.V.A.Rejected):L.validate_plan(changed)
 def test_zero_delta_still_rejects_native_or_annex_change(self):
  inv={'Cargo.lock':'a'*64,'scripts/ci-financial-flow.py':'b'*64}
  self.assertEqual(L.V.equivalent(inv,inv),[])
  with self.assertRaises(L.V.A.Rejected):L.V.equivalent(inv,{**inv,'Cargo.lock':'c'*64})
  with self.assertRaises(L.V.A.Rejected):L.V.equivalent(inv,inv,{})

class WorkflowCustodyTests(unittest.TestCase):
 def test_exact_p_h_and_credential_cleanup_boundaries(self):
  w=(ROOT/'.github/workflows/durable-native-linux.yml').read_text()
  self.assertEqual(w.count('fetch_exact P 99501f5853a4516fc94a6361f39cb4373048f01f'),1)
  self.assertEqual(w.count('fetch_exact H 3fc27434f7ee5d2af5f71c9d9010b982bedf74dd'),1)
  self.assertEqual(w.count('FINANCIAL_ARTIFACT_READ_TOKEN:'),1)
  runtime=w.split('      - name: Actual synthetic financial runtime',1)[1]
  self.assertNotIn('github.token',runtime);self.assertIn('env -i PATH=',runtime)
  self.assertIn("if: always() && steps.mode.outputs.gate == 'financial-semantic-reuse'",runtime)
  self.assertIn('launch_adapter.py" cleanup "${GITHUB_WORKSPACE}/source"',runtime)
 def test_mandatory_launcher_tests_and_no_native_smoke(self):
  w=(ROOT/'.github/workflows/durable-native-linux.yml').read_text()
  self.assertIn("unittest discover -s source/scripts/financial-runtime-reuse -p 'test_*.py'",w)
  smoke=w.split('      - name: Pre-runtime trusted cleanup smoke',1)[1].split('      - name:',1)[0]
  self.assertIn('launch_adapter.py" cleanup',smoke);self.assertNotIn('pristine-setup',smoke);self.assertNotIn(' run ',smoke)

