"""Nonexecuting recipe-v2 fixtures and bounded policy negatives."""
import copy,hashlib,pathlib,tempfile,unittest,zipfile
from test_setup import V
class Tests(unittest.TestCase):
 def setUp(self):
  self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup);self.root=pathlib.Path(self.tmp.name)
  self.inputs=self.root/'inputs';self.inputs.mkdir()
  for n in V.A.NAMES:(self.inputs/n).write_bytes(b'\x7fELFfabricated-never-executable-'+n.encode())
  self.inventory={n:'a'*64 for n in V.RUNTIME_ONLY};self.inventory.update({n:'f'*64 for n in V.A.BUILD_SCRIPTS});self.inventory.update({'Cargo.lock':'b'*64,'scripts/ci-financial-contract.py':'c'*64,'scripts/ci-financial-supervisor.py':'d'*64})
  self.bundle=self.root/'build.tar';V.A.export_bundle(self.inputs,self.bundle,V.PRODUCER,self.inventory,V.QUALIFICATION_PROFILE)
  self.archive=self.root/'download.zip'
  with zipfile.ZipFile(self.archive,'w') as z:z.write(self.bundle,'build.tar')
  self.pins=dict(artifact_id=123,archive_sha256=hashlib.sha256(self.archive.read_bytes()).hexdigest(),bundle_sha256=hashlib.sha256(self.bundle.read_bytes()).hexdigest())
  self.run=dict(id=V.PRODUCER['run_id'],run_attempt=1,head_sha=V.PRODUCER['source'],head_commit={'tree_id':V.PRODUCER['source_tree']},head_branch='qualification/durable-proposal-v1',event='push',status='completed',conclusion='failure',path='.github/workflows/durable-native-linux.yml',repository={'full_name':'stanleykosi/pactloom'})
  self.artifact=dict(id=123,node_id='MDg6QXJ0aWZhY3QxMjQ3ODMxNDMwMg==',name='financial-build-'+str(V.PRODUCER['run_id'])+'-1-'+V.PRODUCER['source'],expired=False,workflow_run={'id':V.PRODUCER['run_id'],'head_sha':V.PRODUCER['source']},digest='sha256:'+self.pins['archive_sha256'])
 def test_v2_recipe_exact(self):
  m=V.A.verify_bundle(self.bundle,V.PRODUCER,self.inventory,V.QUALIFICATION_PROFILE);self.assertEqual(m['version'],2);self.assertEqual(m['recipe']['build_recipe_version'],2)
  for key,value in [('build_recipe_version',1),('observed_rustflags','--cfg wholepact_financial_ci'),('cfg_delivery',{}),('qualification_profile',V.A.PIXEL_PROFILE)]:
   altered=copy.deepcopy(m);altered['recipe'][key]=value
   with self.assertRaises(V.A.Rejected):V.A.validate_manifest(altered,V.PRODUCER,self.inventory,V.QUALIFICATION_PROFILE)
 def test_pixel_rejects_semantic(self):
  with self.assertRaises(V.A.Rejected):V.A.verify_bundle(self.bundle,V.PRODUCER,self.inventory,V.A.PIXEL_PROFILE)
 def test_eight_paths_only_no_native_or_annex(self):
  self.assertEqual(len(V.RUNTIME_ONLY),8)
  for p in V.RUNTIME_ONLY:self.assertEqual(V.equivalent(self.inventory,{**self.inventory,p:'e'*64}),[p])
  for p in set(self.inventory)-V.RUNTIME_ONLY:
   with self.assertRaises(V.A.Rejected):V.equivalent(self.inventory,{**self.inventory,p:'e'*64})
  with self.assertRaises(V.A.Rejected):V.equivalent(self.inventory,self.inventory,{})
 def test_add_delete_rejected(self):
  for h in ({**self.inventory,'scripts/new.py':'f'*64},{k:v for k,v in self.inventory.items() if k!='Cargo.lock'}):
   with self.assertRaises(V.A.Rejected):V.equivalent(self.inventory,h)
 def test_unbound_plan_rejected(self):
  import json
  p=json.loads((pathlib.Path(__file__).parent/'plan.json').read_text())
  p['harness']=None
  with self.assertRaises(V.A.Rejected):V.validate_binding(p)
if __name__=='__main__':unittest.main()

class ExactDiagnosticAnnexTests(unittest.TestCase):
 def sources(self):
  p={k:'a'*64 for k in V.RUNTIME_ONLY};p['Cargo.lock']='b'*64;p['scripts/ci-financial-scenario.py']='c'*64
  h=p.copy()
  for path,pair in V.DIAGNOSTIC_COMPATIBILITY['files'].items():
   p[path]=pair['producer_mode_sha256'];h[path]=pair['harness_mode_sha256']
  return p,h
 def test_exact_reviewed_pairs_only_and_no_annex_requires_original_equality(self):
  p,h=self.sources();annex=copy.deepcopy(V.DIAGNOSTIC_COMPATIBILITY)
  self.assertEqual(set(V.equivalent(p,h,annex)),set(annex['files']))
  self.assertEqual(V.equivalent(p,p),[])
  for a,b,kw in ((p,h,{}),(p,p,{'diagnostic_compatibility':annex}),
    (h,p,{'diagnostic_compatibility':annex}),(p,{**h,'Cargo.lock':'e'*64},{'diagnostic_compatibility':annex}),
    (p,{**h,'scripts/ci-financial-scenario.py':'e'*64},{'diagnostic_compatibility':annex})):
   with self.assertRaises(V.A.Rejected):V.equivalent(a,b,**kw)
 def test_each_pair_required_actual_mode_bound_bytes(self):
  p,h=self.sources();annex=copy.deepcopy(V.DIAGNOSTIC_COMPATIBILITY)
  for path,pair in annex['files'].items():
   for value in (p[path],'e'*64,hashlib.sha256(b'100755\0'+(pathlib.Path(__file__).resolve().parents[2]/path).read_bytes()).hexdigest()):
    with self.assertRaises(V.A.Rejected):V.equivalent(p,{**h,path:value},annex)
   with self.assertRaises(V.A.Rejected):V.equivalent({**p,path:'f'*64},h,annex)
 def test_unknown_missing_swapped_or_mistyped_annex_fields_reject(self):
  base=V.DIAGNOSTIC_COMPATIBILITY;bad=[{},base|{'version':True},base|{'version':2},base|{'name':'future'},base|{'extra':'x'}]
  for path in base['files']:
   missing=copy.deepcopy(base);del missing['files'][path];bad.append(missing)
   extra=copy.deepcopy(base);extra['files']['scripts/ci-financial-scenario.py']=extra['files'][path].copy();bad.append(extra)
   for key in base['files'][path]:
    for value in (True,None,'100755' if key.endswith('_mode') else '0'*40):
     changed=copy.deepcopy(base);changed['files'][path][key]=value;bad.append(changed)
   swapped=copy.deepcopy(base)
   for suffix in ('git_blob','sha256','mode_sha256'):
    a,b='producer_'+suffix,'harness_'+suffix
    swapped['files'][path][a],swapped['files'][path][b]=swapped['files'][path][b],swapped['files'][path][a]
   bad.append(swapped)
  for annex in bad:
   with self.assertRaises(V.A.Rejected):V.validate_diagnostic_compatibility(annex)
