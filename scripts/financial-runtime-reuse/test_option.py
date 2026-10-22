import copy
import hashlib
import pathlib
import tempfile
import unittest
import zipfile
from test_setup import V

class Tests(unittest.TestCase):
 def setUp(self):
  self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup);self.root=pathlib.Path(self.tmp.name)
  self.inputs=self.root/'inputs';self.inputs.mkdir()
  for n in V.A.NAMES:(self.inputs/n).write_bytes(b'\x7fELFfabricated-'+n.encode())
  self.inventory={name:'a'*64 for name in V.RUNTIME_ONLY}
  self.inventory.update({n:'b'*64 for n in ('Cargo.lock','Cargo.toml','crates/native/src/lib.rs',
   'scripts/build-encrypted-storage-deps.sh','scripts/ci-financial-supervisor.py',
   'scripts/ci-financial-artifacts.py','scripts/ci-financial-image.py',
   'scripts/ci-financial-weston-module.c','.github/workflows/durable-native-linux.yml')})
  self.bundle=self.root/'build.tar';V.A.export_bundle(self.inputs,self.bundle,V.PRODUCER,self.inventory)
  self.archive=self.root/'download.zip'
  with zipfile.ZipFile(self.archive,'w') as z:z.write(self.bundle,'build.tar')
  self.pins=dict(artifact_id=123,archive_sha256=hashlib.sha256(self.archive.read_bytes()).hexdigest(),
   bundle_sha256=hashlib.sha256(self.bundle.read_bytes()).hexdigest())
  self.run=dict(id=39792448140,run_attempt=1,head_sha=V.PRODUCER['source'],
   head_branch='qualification/durable-proposal-v1',event='push',status='completed',conclusion='failure',
   path='.github/workflows/durable-native-linux.yml',repository={'full_name':'stanleykosi/pactloom'})
  self.artifact=dict(id=123,name='financial-build-39792448140-1-'+V.PRODUCER['source'],expired=False,
   workflow_run={'id':39792448140,'head_sha':V.PRODUCER['source']},digest='sha256:'+self.pins['archive_sha256'])
  self.harness=dict(repository='stanleykosi/pactloom',source='c'*40,source_tree='d'*40)
 def qualify(self,**kw):
  args=dict(bundle=self.bundle,archive=self.archive,pins=self.pins,run=self.run,artifact=self.artifact,
   producer_inventory=self.inventory,current_inventory=self.inventory,harness=self.harness);args.update(kw)
  return V.qualify(**args)
 def test_permitted_runtime_only_changes_preserve_original_producer(self):
  for path in V.RUNTIME_ONLY:
   changed={**self.inventory,path:'e'*64};result=self.qualify(current_inventory=changed)
   self.assertEqual(result['original_manifest']['closure'],self.inventory)
   self.assertEqual(result['native_producer'],V.PRODUCER)
   self.assertEqual(result['harness'],self.harness)
   self.assertEqual(result['permitted_runtime_changes'],[path])
   self.assertFalse(result['native_binaries_freshly_compiled']);self.assertFalse(result['runtime_verified'])
 def test_all_other_source_inputs_remain_exact(self):
  for path in set(self.inventory)-V.RUNTIME_ONLY:
   with self.assertRaises(V.A.Rejected):self.qualify(current_inventory={**self.inventory,path:'e'*64})
 def test_addition_and_deletion_never_projected_away(self):
  for value in ({**self.inventory,'scripts/new-runtime.py':'e'*64},
                {k:v for k,v in self.inventory.items() if k!='scripts/ci-financial-container.py'}):
   with self.assertRaises(V.A.Rejected):self.qualify(current_inventory=value)
 def test_stale_run_and_wrong_workflow(self):
  for key,value in [('id',39691387835),('run_attempt',2),('head_sha','a'*40),('status','in_progress'),
    ('event','workflow_dispatch'),('path','other.yml'),('conclusion','cancelled'),('repository',{'full_name':'wrong/repo'})]:
   with self.assertRaises(V.A.Rejected):self.qualify(run={**self.run,key:value})
 def test_stale_artifact_or_wrong_origin(self):
  for key,value in [('id',124),('expired',True),('name','ui-build-old'),('digest','sha256:'+'0'*64),
   ('workflow_run',{'id':39691387835,'head_sha':V.PRODUCER['source']})]:
   with self.assertRaises(V.A.Rejected):self.qualify(artifact={**self.artifact,key:value})
 def test_binary_archive_and_hash_mismatch(self):
  for key in ('archive_sha256','bundle_sha256'):
   with self.assertRaises(V.A.Rejected):self.qualify(pins={**self.pins,key:'0'*64})
  self.bundle.chmod(0o600);self.bundle.write_bytes(self.bundle.read_bytes()+b'corrupt')
  with self.assertRaises(V.A.Rejected):self.qualify()
 def test_producer_closure_cannot_be_rewritten(self):
  with self.assertRaises(V.A.Rejected):self.qualify(producer_inventory={**self.inventory,'Cargo.lock':'e'*64})
 def test_recipe_and_features_mismatch(self):
  original=V.A.verify_bundle(self.bundle,V.PRODUCER,self.inventory)
  for key,value in [('coordinator_features','old'),('observed_rustflags',''),('artifact_features',{})]:
   altered=copy.deepcopy(original);altered['recipe'][key]=value
   with self.assertRaises(V.A.Rejected):V.A.validate_manifest(altered,V.PRODUCER,self.inventory)
 def test_private_zip_extra_refused_even_if_archive_pin_matches(self):
  with zipfile.ZipFile(self.archive,'a') as z:z.writestr('private.txt','fabricated')
  pins={**self.pins,'archive_sha256':hashlib.sha256(self.archive.read_bytes()).hexdigest()}
  with self.assertRaises(V.A.Rejected):self.qualify(pins=pins)
 def test_changed_runtime_cannot_claim_producer_identity(self):
  same={k:V.PRODUCER[k] for k in self.harness}
  with self.assertRaises(V.A.Rejected):self.qualify(harness=same,current_inventory={**self.inventory,
   'scripts/ci-financial-container.py':'e'*64})

 def test_p03_producer_identity_is_rejected(self):
  old_source='f98de7fd79389ce340343292086c852825f59b60'
  for key,value in [('id',39704950389),('head_sha',old_source)]:
   with self.assertRaises(V.A.Rejected):self.qualify(run={**self.run,key:value})
  for key,value in [('name','financial-build-39704950389-1-'+old_source),
    ('workflow_run',{'id':39704950389,'head_sha':old_source})]:
   with self.assertRaises(V.A.Rejected):self.qualify(artifact={**self.artifact,key:value})
  original=V.A.verify_bundle(self.bundle,V.PRODUCER,self.inventory)
  old=dict(V.PRODUCER,source=old_source,source_tree='1b4df59f4e2e664cad33440a947645e66424e410',run_id=39704950389)
  with self.assertRaises(V.A.Rejected):V.A.validate_manifest(original,old,self.inventory)

if __name__=='__main__':unittest.main()
