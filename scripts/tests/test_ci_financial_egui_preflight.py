import importlib.util,json,os,pathlib,tempfile,unittest
from unittest import mock
ROOT=pathlib.Path(__file__).resolve().parents[1]
spec=importlib.util.spec_from_file_location('egui_preflight_tested',ROOT/'ci-financial-egui-preflight.py');D=importlib.util.module_from_spec(spec);spec.loader.exec_module(D)
class EguiPreflightBoundaryTests(unittest.TestCase):
 def fixture(self,root):
  target=root/'target';target.mkdir();exe=target/'coordinator-test';exe.write_text('synthetic executable');exe.chmod(0o700)
  rows=[]
  for crate in D.P.SCRIPTS:
   out=target/crate;out.mkdir()
   rows.append(dict(reason='compiler-artifact',package_id=crate,manifest_path=str(D.S.REPO/'crates'/crate/'Cargo.toml'),target=dict(kind=['custom-build'],name='build-script-build',src_path=str(D.S.REPO/'crates'/crate/'build.rs'))))
   rows.append(dict(reason='build-script-executed',package_id=crate,cfgs=list(D.S.A.FINANCIAL_CFGS),linked_libs=[],linked_paths=[],env=[],out_dir=str(out)))
  rows.append(dict(reason='compiler-artifact',manifest_path=str(D.S.REPO/'crates/wholepact-financial-coordinator/Cargo.toml'),profile=dict(test=True),features=D.S.A.RECIPE['artifact_features']['coordinator-observed'],executable=str(exe),filenames=[str(exe)],target=dict(kind=['bin'],name='wholepact-financial-coordinator',src_path=str(D.S.REPO/'crates/wholepact-financial-coordinator/src/main.rs'))))
  return target,exe,rows
 def raw(self,rows):return b'\n'.join(json.dumps(r).encode() for r in rows)
 def test_exact_coordinator_test_binary_four_cfg_consumers(self):
  with tempfile.TemporaryDirectory() as td:
   t,e,r=self.fixture(pathlib.Path(td));self.assertEqual(D.coordinator_test_executable(self.raw(r),t),e)
 def test_wrong_target_profile_feature_cfg_duplicate_and_outside_rejected(self):
  import copy
  with tempfile.TemporaryDirectory() as td:
   t,e,rows=self.fixture(pathlib.Path(td))
   for change in ('kind','name','profile','features','cfg','duplicate','outside','symlink'):
    r=copy.deepcopy(rows)
    if change=='kind':r[-1]['target']['kind']=['lib']
    elif change=='name':r[-1]['target']['name']='wholepact_financial_coordinator'
    elif change=='profile':r[-1]['profile']['test']=1
    elif change=='features':r[-1]['features']=[]
    elif change=='cfg':r[1]['cfgs']=[]
    elif change=='duplicate':r.append(r[-1])
    elif change=='outside':r[-1]['executable']=str(pathlib.Path(td)/'outside')
    elif change=='symlink':
     link=t/'link';link.symlink_to(e);r[-1]['executable']=str(link);r[-1]['filenames']=[str(link)]
    with self.subTest(change=change):
     with self.assertRaises(AssertionError):D.coordinator_test_executable(self.raw(r),t)
 def test_fixed_ignored_list_requires_exact_one_name(self):
  with mock.patch.object(D.S,'checked',return_value=(D.LAYOUT_TEST+': test\n').encode()) as run:
   D.fixed_listing(pathlib.Path('/test'),D.LAYOUT_TEST,{},ignored=True)
   self.assertEqual(run.call_args.args[0],['/test','--list','--exact',D.LAYOUT_TEST,'--ignored'])
  for out in (b'',b'0 tests, 0 benchmarks\n',(D.LAYOUT_TEST+': test\n'+D.LAYOUT_TEST+': test\n').encode()):
   with mock.patch.object(D.S,'checked',return_value=out):
    with self.assertRaises(AssertionError):D.fixed_listing(pathlib.Path('/test'),D.LAYOUT_TEST,{},ignored=True)
 def test_private_dto_metadata_does_not_read_content_and_rejects_wrong_mode_link_oversize(self):
  with tempfile.TemporaryDirectory() as td:
   p=pathlib.Path(td)/'dto';p.write_bytes(b'private synthetic bytes');p.chmod(0o600)
   with mock.patch.object(pathlib.Path,'read_bytes',side_effect=AssertionError('no read')):self.assertEqual(D.private_dto(p),(p.stat().st_dev,p.stat().st_ino))
   p.chmod(0o644)
   with self.assertRaises(AssertionError):D.private_dto(p)
   p.chmod(0o600);link=pathlib.Path(td)/'link';link.symlink_to(p)
   with self.assertRaises(AssertionError):D.private_dto(link)
   with p.open('wb') as f:f.truncate(60*1024+1)
   with self.assertRaises(AssertionError):D.private_dto(p)
 def test_workflow_is_checkpoint_only_no_upload_or_qualification_activation(self):
  s=(ROOT.parent/'.github/workflows/egui-layout-preflight.yml').read_text()
  self.assertIn('branches: [checkpoint/egui-layout-d62c]',s);self.assertIn('permissions: {}',s);self.assertIn('timeout-minutes: 45',s)
  for forbidden in ('upload-artifact','qualification/durable-proposal-v1','secrets.','--release','workflow_dispatch'):self.assertNotIn(forbidden,s)

 def test_export_marker_is_one_closed_finite_record_not_raw_output(self):
  good=b'EGUI_ADMIT_FIXTURE_V1 {"bytes":40000,"material_input_id_bytes":75,"public_dto_valid":true}'
  self.assertEqual(D.export_measurement(good)['bytes'],40000)
  for raw in (b'',good+b'\n'+good,good.replace(b'40000',b'true'),good.replace(b'40000',b'999999'),good.replace(b'"bytes":',b'"secret":"private","bytes":'),good.replace(b'true',b'false')):
   with self.assertRaises((AssertionError,ValueError)):D.export_measurement(raw)

 def test_layout_summary_rejects_raw_text_unknown_payload_duplicate_and_oversize(self):
  good=b'{"schema":1,"outcome":"diagnostic_setup_rejected"}'
  self.assertEqual(D.layout_summary(good)['outcome'],'diagnostic_setup_rejected')
  for raw in (b'private report text',good.replace(b'"schema":1',b'"schema":1,"schema":1'),good.replace(b'"schema":1',b'"private":"raw","schema":1'),b'x'*16385,b'\xff'):
   with self.assertRaises((AssertionError,ValueError)):D.layout_summary(raw)
