"""Fixed diagnostic boundary tests; no Docker, sockets, network or native ELF."""
import contextlib,copy,hashlib,importlib.util,io,json,os,pathlib,types,unittest
from unittest.mock import Mock,patch
HERE=pathlib.Path(__file__).resolve().parent
spec=importlib.util.spec_from_file_location('diagnostic_adapter_test',HERE/'diagnostic_adapter.py');D=importlib.util.module_from_spec(spec);spec.loader.exec_module(D)
W=D.load_verified(HERE.parent/'ci-synthetic-output.py',D.WRAPPER_SHA)
CORE=b'[JOINED_CORE_POLICY inherited_limit=Zero collector=File process_dumpability=Unchanged crash_copy_absence_verified=false]'
def row():
 r={k:True for k in W.DURABLE_DELIVERY_BOOL_FIELDS};r.update({k:False for k in W.DURABLE_DELIVERY_FALSE_FIELDS})
 r.update(schema=4,phase='durable_delivery_admission',result='passed',first_failure=None,first_outcome=None,retained_exporter_failure=None,retained_exporter_outcome=None,failed_child_inputs_completed=None,failed_child_inputs_expected=None,producer_exit='sigkill',reader_exit='success',root_cleanup='closed_absent',admission_count='2_of_2');return r
def line(r):return W.DURABLE_DELIVERY_PREFIX.encode()+json.dumps(r,separators=(',',':')).encode()
class OutputTests(unittest.TestCase):
 def test_exact_existing_target_and_bounds(self):
  self.assertNotIn(D.PHASE,W.DURABLE_DIAGNOSTIC_PHASES);self.assertEqual(W.TESTS[D.PHASE],(D.TEST,1080));name,seconds,flags=W.phase_selection(D.PHASE)
  self.assertEqual(flags,['--exact',D.TEST,'--test-threads=1','--ignored'])
 def test_success_is_diagnostic_only(self):
  r=D.Records(W);r(CORE);r(line(row()));r(b'CI_SYNTHETIC_RESULT phase=durable-delivery-admission passed=true cleanup_verified=true');self.assertTrue(r.finish(0))
  out=io.StringIO()
  with contextlib.redirect_stdout(out):D.emit_result('complete',True,True,r)
  lines=out.getvalue().splitlines();self.assertEqual(len(lines),2);v=json.loads(lines[-1].split(' ',1)[1]);self.assertTrue(v['diagnostic_passed']);self.assertFalse(v['full_flow_verified']);self.assertFalse(v['coordinated_pair_verified']);self.assertFalse(v['dispatch_requested'])
 def test_native_timeout_never_upgraded_by_container_cleanup(self):
  r=D.Records(W);r(b'CI_SYNTHETIC_RESULT cleanup_unverified=true outcome_unverified=true');r(b'CI_SYNTHETIC_RESULT passed=false details_withheld=true');self.assertFalse(r.finish(1));out=io.StringIO()
  with contextlib.redirect_stdout(out):D.emit_result('wrapper',False,True,r)
  v=json.loads(out.getvalue().split(' ',1)[1]);self.assertTrue(v['wrapper_cleanup_unverified']);self.assertFalse(v['native_wrapper_cleanup_verified']);self.assertTrue(v['container_image_cache_cleanup_verified'])
 def test_invalid_private_extra_duplicate_missing_and_wrong_status_reject(self):
  for raw in (b'PRIVATE secret /wallet',line({**row(),'private':'secret'}),line({**row(),'schema':3}),b'CI_SYNTHETIC_DURABLE_DELIVERY '+b'x'*2049):
   r=D.Records(W)
   with self.assertRaises(Exception):r(raw)
   self.assertTrue(r.invalid);self.assertIsNone(r.row)
  r=D.Records(W);r(line(row()))
  with self.assertRaises(Exception):r(line(row()))
  self.assertIsNone(r.row)
  r=D.Records(W);r(b'CI_SYNTHETIC_RESULT phase=durable-delivery-admission passed=true cleanup_verified=true')
  with self.assertRaises(Exception):r.finish(0)
 def test_cleanup_failure_blocks_pass(self):
  out=io.StringIO()
  with contextlib.redirect_stdout(out):D.emit_result('cleanup',True,False,None)
  self.assertFalse(json.loads(out.getvalue().split(' ',1)[1])['diagnostic_passed'])
 def test_original_cleanup_stdout_suppressed(self):
  L=Mock();L.trusted_cleanup.side_effect=lambda _: print('RAW PRIVATE') or True;out=io.StringIO()
  with contextlib.redirect_stdout(out):self.assertTrue(D.trusted_cleanup(L,object()))
  self.assertEqual(out.getvalue(),'')
class WrapperReplayTests(unittest.TestCase):
 def test_existing_wrapper_full_stdout_shape_replays_without_raw_native_text(self):
  process=Mock();process.stdout=Mock();process.stdout.fileno.return_value=8;process.wait.return_value=0
  listed=types.SimpleNamespace(stdout=(D.TEST+': test\n\n1 test, 0 benchmarks\n').encode(),stderr=b'')
  native=CORE+b'\n'+line(row())+b'\nPRIVATE RAW WALLET MATERIAL\n'
  out=io.StringIO()
  with patch.object(W.resource,'getrlimit',return_value=(0,0)),patch.object(W.subprocess,'run',return_value=listed),patch.object(W.subprocess,'Popen',return_value=process),patch.object(W.select,'select',return_value=([process.stdout],[],[])),patch.object(W.os,'read',side_effect=[native,b'']),contextlib.redirect_stdout(out):
   W.run('/fixed/pristine-setup',D.PHASE)
  self.assertNotIn('PRIVATE RAW',out.getvalue());r=D.Records(W)
  for raw in out.getvalue().splitlines():r(raw.encode())
  self.assertTrue(r.finish(0));self.assertEqual(r.row,row())

class FailureWrapperReplayTests(unittest.TestCase):
 def test_existing_wrapper_failure_stdout_is_only_sanitized(self):
  process=Mock();process.stdout=Mock();process.stdout.fileno.return_value=8;process.wait.return_value=1
  listed=types.SimpleNamespace(stdout=(D.TEST+': test\n\n1 test, 0 benchmarks\n').encode(),stderr=b'')
  failed=dict(row(),result='failed',first_failure='DeliveryReceiveDeadline',first_outcome='PredicateDenied',failed_child_inputs_completed=113,failed_child_inputs_expected=121,admission_count='unverified',reader_exit='not_started',reader_reaped=False,reader_group_absent=False,reader_no_effects_verified=False)
  native=CORE+b'\n'+line(failed)+b'\nPRIVATE RAW MATERIAL\n';out=io.StringIO()
  with patch.object(W.resource,'getrlimit',return_value=(0,0)),patch.object(W.subprocess,'run',return_value=listed),patch.object(W.subprocess,'Popen',return_value=process),patch.object(W.select,'select',return_value=([process.stdout],[],[])),patch.object(W.os,'read',side_effect=[native,b'']),contextlib.redirect_stdout(out):
   with self.assertRaises(Exception):W.run('/fixed/pristine-setup',D.PHASE)
  self.assertNotIn('PRIVATE RAW',out.getvalue())
  r=D.Records(W)
  for raw in out.getvalue().splitlines():r(raw.encode())
  # Wrapper main emits its fixed generic failure after run() raises.
  r(b'CI_SYNTHETIC_RESULT passed=false details_withheld=true');self.assertFalse(r.finish(1));self.assertEqual(r.row,failed)

class IsolationTests(unittest.TestCase):
 def setUp(self):
  self.S=Mock();self.S.LABEL='run';self.S.SOURCE_LABEL='source';self.S.TMPFS={'/tmp':'rw,noexec,nosuid,nodev,size=64m,uid=10001,gid=10001,mode=0700'};self.S.B.absent=lambda v:v in (None,[],{})
  self.r=dict(Image='sha256:abc',Config=dict(Labels={'run':'token','source':'commit'},Image='sha256:abc',User='10001:10001',Entrypoint=D.ENTRYPOINT.copy(),Cmd=[],WorkingDir='/opt/ci-financial',Volumes={},Env=['CARGO_TARGET_DIR=/opt/ci-financial','TMPDIR=/tmp']),HostConfig=dict(NetworkMode='none',ReadonlyRootfs=True,Privileged=False,CapDrop=['ALL'],CapAdd=None,SecurityOpt=['no-new-privileges:true'],PidMode='',IpcMode='private',UsernsMode='',CgroupnsMode='private',GroupAdd=None,LogConfig={'Type':'none','Config':{}},RestartPolicy={'Name':'no','MaximumRetryCount':0},AutoRemove=False,PidsLimit=128,Memory=2*1024**3,MemorySwap=2*1024**3,NanoCpus=2_000_000_000,Binds=None,Devices=None,DeviceRequests=None,Mounts=None,Tmpfs=self.S.TMPFS.copy(),Ulimits=[{'Name':'core','Hard':0,'Soft':0},{'Name':'nofile','Hard':512,'Soft':512}]),Mounts=[{'Type':'tmpfs','Destination':'/tmp','Source':''}])
 def check(self):
  self.S.loads.return_value=[self.r];D.inspect_container(self.S,'name','token','sha256:abc','commit')
 def test_exact_isolation_accepts(self):self.check()
 def test_weakened_host_controls_reject(self):
  base=copy.deepcopy(self.r)
  for key,value in [('NetworkMode','host'),('ReadonlyRootfs',False),('Privileged',True),('CapAdd',['SYS_ADMIN']),('PidsLimit',129),('MemorySwap',0),('Binds',['/private:/private']),('LogConfig',{'Type':'json-file'}),('Ulimits',[{'Name':'core','Hard':-1,'Soft':-1}])]:
   self.r=copy.deepcopy(base);self.r['HostConfig'][key]=value
   with self.assertRaises(Exception):self.check()
 def test_wrong_command_uid_credentials_reject(self):
  base=copy.deepcopy(self.r)
  for key,value in [('User','0:0'),('Entrypoint',['/bin/sh']),('Cmd',['full']),('Env',['CARGO_TARGET_DIR=/opt/ci-financial','TMPDIR=/tmp','TOKEN=secret'])]:
   self.r=copy.deepcopy(base);self.r['Config'][key]=value
   with self.assertRaises(Exception):self.check()
 def test_fixed_creation_no_extra_caps_and_same_owned_slot(self):
  S=self.S;S.names.return_value=[];S.command.return_value=(0,b'closed\n');records=Mock();records.finish.return_value=True
  with patch.object(D,'inspect_container'):self.assertTrue(D.run_container(S,'sha256:abc','token','commit',records))
  args=S.docker.call_args.args[0];self.assertIn('wp-financial-token-external',args);self.assertNotIn('--cap-add',args);self.assertEqual(args[-1],'sha256:abc');self.assertEqual(S.command.call_args.kwargs['seconds'],1140)
 def test_existing_job_slot_blocks_create(self):
  self.S.names.return_value=['wp-financial-token-external']
  with self.assertRaises(Exception):D.run_container(self.S,'image','token','commit',Mock())
  self.S.docker.assert_not_called()
class BootstrapTests(unittest.TestCase):
 def test_wrong_context_rejects_before_any_helper(self):
  with patch.dict(os.environ,{'PATH':'/bin'},clear=True),patch.object(D.subprocess,'check_output') as git:
   with self.assertRaises(Exception):D.bootstrap('/untrusted')
   git.assert_not_called()
 def test_main_invalid_arguments_only_finite_output(self):
  out=io.StringIO()
  with patch.object(D.sys,'argv',['adapter','secret']),contextlib.redirect_stdout(out):self.assertEqual(D.main(),1)
  self.assertNotIn('secret',out.getvalue());self.assertEqual(len(out.getvalue().splitlines()),1)
 def test_cleanup_only_has_one_finite_result(self):
  out=io.StringIO()
  with patch.object(D.sys,'argv',['adapter','cleanup','L']),patch.object(D,'bootstrap',return_value=(Mock(),Mock())),patch.object(D,'trusted_cleanup',return_value=True) as cleanup,contextlib.redirect_stdout(out):self.assertEqual(D.main(),0)
  cleanup.assert_called_once();self.assertEqual(len(out.getvalue().splitlines()),1);self.assertTrue(out.getvalue().startswith('CI_PREPARATION_DIAGNOSTIC_CLEANUP '));self.assertNotIn('diagnostic_passed',json.loads(out.getvalue().split(' ',1)[1]))
class ImageFailureTests(unittest.TestCase):
 def setUp(self):
  self.S=types.SimpleNamespace(PACKAGE_CHECKS=frozenset(('download_digest','download_failed')),CHECKS=frozenset(('command_failed','image_identity')),IMAGE_CHECKS=frozenset(('tool_exit','input_digest','internal')),IMAGE_PHASES=frozenset(('install','inputs')),loads=lambda raw:json.loads(raw,object_pairs_hook=self.unique))
 def unique(self,pairs):
  value={}
  for key,item in pairs:
   if key in value:raise ValueError('duplicate')
   value[key]=item
  return value
 def error(self,**kwargs):
  e=ValueError('PRIVATE secret /wallet https://credential.invalid');e.__dict__.update(kwargs);return e
 def test_actual_pinned_package_errors_keep_reviewed_codes(self):
  S=D.load_verified(HERE.parent/'ci-financial-supervisor.py',name='diagnostic_actual_supervisor')
  B=D.load_verified(HERE.parent/'ci-ui-image.py',name='diagnostic_actual_packages')
  for code in ('staging_directory','manifest_pin','manifest_shape','closure','download_origin','download_digest'):
   r=D.image_failure_record(S,'context_manifest',B.Rejected(code));self.assertEqual(r['code'],code)
  self.assertEqual(D.image_failure_record(S,'context',B.Rejected('PRIVATE'))['code'],'unavailable')
 def test_context_download_failure_preserves_closed_code_no_exception(self):
  out=io.StringIO();p=D.ImageProgress(self.S)
  def fail():p.advance('context_download');raise self.error(code='download_digest',cleanup_failed=False)
  with contextlib.redirect_stdout(out),self.assertRaises(ValueError):p.perform('context',fail)
  text=out.getvalue();r=json.loads(text.split(' ',1)[1]);self.assertEqual(r['operation'],'context_download');self.assertEqual(r['code'],'download_digest');self.assertFalse(r['native_started']);self.assertNotIn('PRIVATE',text);self.assertNotIn('wallet',text)
 def test_build_only_exact_installer_metadata_preserved(self):
  installer=dict(schema_version=1,phase='install',code='tool_exit',cleanup_failed=False)
  error=self.error(code='command_failed',exit_status=1,output=b'PRIVATE raw secret\n#9 0.2 '+json.dumps(installer).encode()+b'\n')
  r=D.image_failure_record(self.S,'image_build',error);self.assertEqual(r['installer'],installer);self.assertTrue(r['installer_record_available']);self.assertEqual(r['exit_status'],1);self.assertNotIn('PRIVATE',json.dumps(r))
  self.assertIsNone(D.image_failure_record(self.S,'base_pull',error)['installer'])
 def test_missing_invalid_duplicate_and_oversized_records_unavailable(self):
  good=b'{"schema_version":1,"phase":"install","code":"tool_exit","cleanup_failed":false}'
  for raw in (b'PRIVATE',good+b'\n'+good.replace(b'tool_exit',b'internal'),good.replace(b'"phase":"install"',b'"phase":"PRIVATE"'),good[:-1]+b',"raw":"secret"}',good.replace(b'"schema_version":1',b'"schema_version":true'),good.replace(b'"schema_version":1',b'"schema_version":1,"schema_version":1'),b'x'*(8*1024*1024+1)):
   r=D.image_failure_record(self.S,'image_build',self.error(code='PRIVATE',exit_status=True,output=raw));self.assertFalse(r['installer_record_available']);self.assertIsNone(r['installer']);self.assertEqual(r['code'],'unavailable');self.assertIsNone(r['exit_status'])
 def test_identical_buildkit_recap_deduplicates(self):
  value=dict(schema_version=1,phase='install',code='tool_exit',cleanup_failed=False)
  raw=json.dumps(value).encode();r=D.image_failure_record(self.S,'image_build',self.error(output=raw+b'\n#recap '+raw))
  self.assertTrue(r['installer_record_available']);self.assertEqual(r['installer'],value)
 def test_broken_stdout_preserves_original_failure(self):
  original=self.error(code='download_failed');p=D.ImageProgress(self.S)
  def fail():raise original
  with patch('builtins.print',side_effect=BrokenPipeError):
   with self.assertRaises(ValueError) as caught:p.perform('context',fail)
  self.assertIs(caught.exception,original)
 def test_projection_failure_preserves_original_failure(self):
  original=self.error(code='download_failed');p=D.ImageProgress(self.S)
  def fail():raise original
  with patch.object(D,'image_failure_record',side_effect=RuntimeError('projection')):
   with self.assertRaises(ValueError) as caught:p.perform('context',fail)
  self.assertIs(caught.exception,original)
 def test_operations_are_closed_and_success_silent(self):
  p=D.ImageProgress(self.S);out=io.StringIO()
  with contextlib.redirect_stdout(out):self.assertEqual(p.perform('base_pull',lambda:42),42)
  self.assertEqual(out.getvalue(),'')
  with self.assertRaises(Exception):p.advance('PRIVATE')
 def test_each_process_operation_preserves_only_its_fixed_identity(self):
  for operation in ('base_pull','image_build','image_descriptor','source_recheck'):
   p=D.ImageProgress(self.S);out=io.StringIO()
   def fail():raise self.error(code='command_failed',exit_status=7,output=b'PRIVATE')
   with contextlib.redirect_stdout(out),self.assertRaises(ValueError):p.perform(operation,fail)
   r=json.loads(out.getvalue().split(' ',1)[1]);self.assertEqual(r['operation'],operation);self.assertEqual(r['exit_status'],7);self.assertNotIn('PRIVATE',out.getvalue())

if __name__=='__main__':unittest.main()
