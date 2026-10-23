"""Private unbound scaffold wiring; never activate or execute native artifacts."""
import hashlib,json,pathlib,unittest
from test_setup import L,TRUSTED
HERE=pathlib.Path(__file__).resolve().parent
ROOT=HERE.parents[1]
class IntegrationTests(unittest.TestCase):
 def test_concrete_identical_source_v2_plan(self):
  p=json.loads((HERE/'plan.json').read_text());self.assertEqual(p['harness'],{k:L.V.PRODUCER[k] for k in ('repository','source','source_tree')})
  self.assertEqual(L.validate_plan(p),p)
  self.assertEqual(p['producer'],L.V.PRODUCER);self.assertEqual(p['artifact_pins'],L.V.ARTIFACT_PINS);self.assertEqual(p['api_pins'],L.V.API_PINS)
  self.assertEqual(p['manifest_version'],2);self.assertEqual(p['build_recipe_version'],2);self.assertEqual(p['version'],6)
  self.assertEqual(p['artifact_pins']['artifact_id'],12483805195)
 def test_p35_parser_and_cleanup_exact_current_sources(self):
  self.assertEqual((HERE/'producer_artifacts.py').read_bytes(),(ROOT/'scripts/ci-financial-artifacts.py').read_bytes())
  for path,pin in L.CLEANUP_PINS.items():
   data=(HERE/path).read_bytes();self.assertEqual(hashlib.sha256(data).hexdigest(),pin)
   if path=='cleanup_snapshot/scripts/ci-financial-contract.py':
    # Dormant P35 cleanup bytes stay pinned; fresh P40 uses its reviewed current contract.
    self.assertEqual(hashlib.sha256((ROOT/'scripts/ci-financial-contract.py').read_bytes()).hexdigest(),'501993b6ee0bed7db09aa6d3722381e58e051c39cc6cae020bf5f42d47cadfa8')
   else:self.assertEqual(data,b'financial-semantic\n' if path.endswith('/qualification-gate-mode') else (ROOT/pathlib.Path(path).relative_to('cleanup_snapshot')).read_bytes())
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
  fresh=w.split('      - name: Fresh isolated two-signer financial UI',1)[1].split('      - name:',1)[0]
  self.assertIn("steps.mode.outputs.gate == 'financial-semantic'",fresh)
  self.assertIn('run: bash scripts/ci-financial-linux.sh',fresh)
  for title in ('Fetch exact independent producer P and reviewed harness H without credentials','Acquire exact producer bundle with isolated read token','Actual synthetic financial runtime using verified producer binaries (not a fresh build)','Preserved P35 preparation, owned admissions and process-death reopen diagnostic (NOT full flow)'):
   block=w.split('      - name: '+title,1)[1].split('      - name:',1)[0]
   condition=next(line for line in block.splitlines() if line.strip().startswith('if:'))
   self.assertNotIn("gate == 'financial-semantic'",condition)
  cleanup=w.split('      - name: Verify financial containers, temporary images and build cache removed',1)[1].split('      - name:',1)[0]
  self.assertIn("always() &&",cleanup);self.assertIn("gate == 'financial-semantic'",cleanup)
  self.assertIn('scripts/ci-financial-supervisor.py cleanup',cleanup)
if __name__=='__main__':unittest.main()

class CleanupProfileTests(unittest.TestCase):
 def test_current_p35_cleanup_main_has_pinned_profile_input(self):
  from unittest.mock import patch
  import tempfile,os
  s=TRUSTED.module('cleanup_main_probe',L.HERE/'cleanup_snapshot/scripts/ci-financial-supervisor.py')
  with tempfile.TemporaryDirectory() as tmp,patch.dict(os.environ,{'RUNNER_TEMP':tmp}),patch.object(s,'context',return_value=('a'*40,'token')),patch.object(s.sys,'argv',['supervisor','cleanup']),patch.object(s,'cleanup',return_value=True) as cleanup,patch.object(s,'emit'):
   self.assertEqual(s.main(),0);cleanup.assert_called_once()

class IdenticalSourceTests(unittest.TestCase):
 def test_zero_delta_only_for_exact_producer_identity(self):
  p=json.loads((HERE/'plan.json').read_text());self.assertEqual(p['reviewed_runtime_changes'],{});L.validate_plan(p)
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
  self.assertEqual(w.count('fetch_exact P 8f145cf7a4f90346fad22fc1dd2c600aa8f7db02'),1)
  self.assertEqual(w.count('fetch_exact H 8f145cf7a4f90346fad22fc1dd2c600aa8f7db02'),1)
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

