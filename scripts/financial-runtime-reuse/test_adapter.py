import contextlib
import copy
import importlib.util
import io
import json
import os
import pathlib
import tempfile
import unittest
from unittest.mock import patch
from test_setup import L,A

BASE=pathlib.Path(__file__).resolve().parents[3]/'H'
if not BASE.is_dir():BASE=pathlib.Path(__file__).resolve().parents[3]/'pactloom-financial-private-composed35'
assert __import__('hashlib').sha256((BASE/'scripts/ci-financial-supervisor.py').read_bytes()).hexdigest()=='2b251c9f0bcce7a227d7e7f37f2a7a51c049f6b0e30e36ee3c11adce19c6dce0'
spec=importlib.util.spec_from_file_location('current_fresh_supervisor',BASE/'scripts/ci-financial-supervisor.py')
S=importlib.util.module_from_spec(spec);spec.loader.exec_module(S)

class AdapterTests(unittest.TestCase):
 def plan(self):
  p=json.loads((pathlib.Path(__file__).resolve().parent/'plan.json').read_text());p['harness']=dict(repository='stanleykosi/pactloom',source='c'*40,source_tree='d'*40);p['reviewed_runtime_changes']={'scripts/ci-financial-observer.py':'d'*64};return p
 def test_unpinned_future_artifact_cannot_activate(self):
  p=self.plan();self.assertEqual(L.validate_plan(p),p)
  for key,value in [('artifact_pins',None),('harness',None),('producer',{}),('producer',{**L.V.PRODUCER,'attempt':True}),('reviewed_runtime_changes',{}),
   ('reviewed_runtime_changes',{'scripts/ci-financial-supervisor.py':'a'*64})]:
   with self.assertRaises(L.V.A.Rejected):L.validate_plan({**p,key:value})
  p['producer']['source']='b85e126eee1067a17f34b21e4abf1c3b767db166'
  with self.assertRaises(L.V.A.Rejected):L.validate_plan(p)
 def test_p26_versioned_policy_rejects_unreviewed_annex(self):
  p=self.plan();self.assertEqual(L.validate_plan(p),p)
  for changed in ({**p,'version':1},{**p,'version':2},{**p,'version':3},{**p,'version':4},{**p,'version':True},
                  {k:v for k,v in p.items() if k!='manifest_version'},{**p,'diagnostic_compatibility':{}},{**p,'transition_compatibility':{}},
                  {**p,'transition_compatibility':None}, {**p,'policy':'p23-rendered-host-semantic-reuse-v1'},
                  {**p,'qualification_profile':L.V.A.PIXEL_PROFILE},
                  {**p,'reviewed_runtime_changes':{'scripts/ci-financial-scenario.py':'a'*64}}):
   with self.assertRaises(L.V.A.Rejected):L.validate_plan(changed)
 def test_acquisition_credentials_never_accepted_in_runtime_process(self):
  with patch.dict(os.environ,{'PATH':'/bin'},clear=True):self.assertEqual(set(L.safe_environment()),
   {'PATH','HOME','GIT_CONFIG_NOSYSTEM','GIT_CONFIG_GLOBAL','GIT_TERMINAL_PROMPT'})
  for key in ('GITHUB_TOKEN','API_PASSWORD','ACTIONS_RUNTIME_TOKEN','SECRET_VALUE'):
   with patch.dict(os.environ,{'PATH':'/bin',key:'fabricated'},clear=True):
    with self.assertRaises(L.V.A.Rejected):L.safe_environment()
 def test_producer_job_requires_successful_exact_upload(self):
  j=dict(id=L.V.JOB_ID,run_id=L.V.PRODUCER['run_id'],name='synthetic-only',status='completed',conclusion='failure',
   steps=[dict(name='Preserve exact credential-free compiled financial bundle',status='completed',conclusion='success')])
  L.validate_job(j)
  for changed in ({**j,'id':1},{**j,'steps':[]},{**j,'status':'in_progress'},{**j,'steps':j['steps']*2}):
   with self.assertRaises(L.V.A.Rejected):L.validate_job(changed)
 def test_runtime_command_trace_equals_current_fresh_main(self):
  def collect(fresh):
   calls=[]
   def call(name,result=None):
    def record(*a,**kw):calls.append((name,a,kw));return result
    return record
   with tempfile.TemporaryDirectory() as tmp:
    root=pathlib.Path(tmp)/'owned';root.mkdir()
    with patch.dict(os.environ,{'RUNNER_TEMP':tmp}),patch.object(S,'context',return_value=('c'*40,'token')),patch.object(S.sys,'argv',['script','run']), \
     patch.object(S.tempfile,'mkdtemp',return_value=str(root)),patch.object(S,'exact_source'), \
     patch.object(S,'emit'),patch.object(S,'build_inputs',return_value='context'), \
     patch.object(S,'docker',side_effect=call('docker')), \
     patch.object(S,'build_image',side_effect=call('build_image',{'id':'foundation'})), \
     patch.object(S,'final_image',side_effect=call('final_image','runtime')), \
     patch.object(S,'run_case',side_effect=call('run_case',({'native_oracle_verified':True},True))), \
     patch.object(S,'cleanup',return_value=True):
     if fresh:self.assertEqual(S.main(),0)
     else:L.runtime_commands(S,'context','token','c'*40)
   return calls
  self.assertEqual(collect(True),collect(False))
 def test_real_runtime_creation_policy_is_unchanged(self):
  commands=[]
  candidate=b'CI_FINANCIAL_CANDIDATE '+json.dumps(dict(schema=1,profile=S.P.C.SEMANTIC_PROFILE,
   native_oracle_verified=True,fixture_cleaned=True,display_cleaned=True,public_chain_verified=False,
   dispatch_attempted=False)).encode()
  def command(args,stage,**kw):
   commands.append((args,stage,kw));kw['on_line'](candidate);return 0,b''
  with patch.object(S,'names',return_value=[]),patch.object(S,'docker',side_effect=lambda *a,**k:commands.append((a,k))), \
   patch.object(S,'inspect_isolation'),patch.object(S,'remove_container'),patch.object(S,'command',side_effect=command), \
   patch.object(S,'docker_env',return_value={'PATH':'/bin'}):
   result,passed=S.run_case('external','image','token','c'*40)
  self.assertTrue(passed)
  create=commands[0][0][0]
  for item in ('--read-only','--cap-drop','ALL','no-new-privileges:true','--pids-limit','128','2g',
    '--network','none','--ipc','private','--cgroupns','--ulimit','core=0:0','nofile=512:512','--log-driver','no'):
   if item=='no':continue
   self.assertIn(item,create)
  attach=commands[1];self.assertEqual(attach[0],['docker','start','--attach','wp-financial-token-external'])
  self.assertEqual(attach[2]['seconds'],1830);self.assertEqual(attach[2]['limit'],16384)
 def owned(self,*,cleanup=True,test_failure=False):
  with tempfile.TemporaryDirectory() as tmp:
   root=pathlib.Path(tmp)/'owned';root.mkdir();records=[];plan=self.plan()
   with patch.object(S,'exact_source'),patch.object(S,'checked',side_effect=S.Failure('preflight','internal') if test_failure else None) as checked, \
    patch.object(L,'safe_environment',return_value={'PATH':'/bin'}), \
    patch.object(L,'acquire_verified_inputs',return_value=(root/'artifacts',{})) as acquire, \
    patch.object(L,'digest',return_value='a'*64),patch.object(L,'stage_image_context',return_value='context'), \
    patch.object(L,'runtime_commands',return_value=({'native_oracle_verified':True},True)) as runtime, \
    patch.object(S,'cleanup',return_value=cleanup),patch.object(S,'emit',side_effect=lambda *a:records.append(a)):
    status=L.run_owned(S,root,'staging',plan,{}, {},{'source':'e'*40},'token')
   self.assertFalse(root.exists())
   return status,records,acquire,runtime,checked
 def test_cleanup_failure_cannot_be_masked_by_successful_reuse(self):
  status,records,*_=self.owned(cleanup=False)
  self.assertEqual(status,1);self.assertFalse(records[-1][1]['synthetic_external_witness_flow_verified'])
 def test_mandatory_tests_precede_artifact_staging_and_runtime(self):
  status,records,acquire,runtime,checked=self.owned(test_failure=True)
  self.assertEqual(status,1);acquire.assert_not_called();runtime.assert_not_called()
 def test_success_labels_all_roles_and_never_fresh(self):
  status,records,acquire,runtime,checked=self.owned()
  self.assertEqual(status,0);result=records[-1][1]
  self.assertEqual(result['native_producer'],L.V.PRODUCER);self.assertEqual(result['harness'],self.plan()['harness'])
  self.assertEqual(result['launcher'],{'source':'e'*40});self.assertFalse(result['native_binaries_freshly_compiled'])
  self.assertFalse(result['synthetic_full_native_verified']);self.assertFalse(result['dispatch_requested'])
  self.assertEqual(result['profile'],L.V.QUALIFICATION_PROFILE)
  self.assertTrue(result['semantic_assisted_host_observation']);self.assertFalse(result['pixel_only_ui_verified'])
  self.assertEqual(checked.call_count,2)
  self.assertIn('test*financial*.py',checked.call_args_list[1].args[0])



class AcquisitionTests(unittest.TestCase):
 def test_redirect_allowlist_never_allows_arbitrary_or_authenticated_urls(self):
  from test_setup import A
  self.assertEqual(A.redirect_target('https://results.blob.core.windows.net/a?sig=fabricated'),
                   'https://results.blob.core.windows.net/a?sig=fabricated')
  for url in ('http://results.blob.core.windows.net/a','https://api.github.com/a',
   'https://results.blob.core.windows.net.evil.test/a','https://user@results.blob.core.windows.net/a',
   'https://results.blob.core.windows.net:444/a','file:///private'):
   with self.assertRaises(A.L.V.A.Rejected):A.redirect_target(url)
 def test_bounded_download_rejects_size_and_deadline(self):
  from test_setup import A
  with self.assertRaises(A.L.V.A.Rejected):A.bounded_read(io.BytesIO(b'12345'),4,float('inf'))
  with self.assertRaises(A.L.V.A.Rejected):A.bounded_read(io.BytesIO(b'1'),4,0)
 def test_no_redirect_handler_cannot_forward_authorization(self):
  from test_setup import A
  self.assertIsNone(A.NoRedirect().redirect_request(None,None,None,None,None,None))

class IdentityTests(unittest.TestCase):
 plan=AdapterTests.plan
 def identities(self,change=None):
  plan=self.plan();p_inv={k:'a'*64 for k in L.V.RUNTIME_ONLY};p_inv['Cargo.lock']='b'*64
  h_inv={**p_inv,**plan['reviewed_runtime_changes']}
  p_inv['scripts/ci-financial-scenario.py']='b'*64;h_inv['scripts/ci-financial-scenario.py']='b'*64
  if change:h_inv.update(change)
  mapping={str(pathlib.Path('/P')):(L.V.PRODUCER['source_tree'],p_inv),
           str(pathlib.Path('/H')):(plan['harness']['source_tree'],h_inv),
           str(pathlib.Path('/L')):('e'*40,{'adapter.py':'f'*64})}
  with patch.dict(os.environ,{'GITHUB_SHA':'f'*40}),patch.object(L,'HERE',pathlib.Path('/L/scripts')), \
       patch.object(L,'safe_environment'),patch.object(L.V,'inventory_checkout',side_effect=lambda root,sha:mapping[str(root)]):
   return L.verify_sources(plan,'/P','/H','/L')
 def test_version5_source_verification_keeps_runtime_hash_review_exact(self):
  self.identities()
  for changes in ({'Cargo.lock':'e'*64},
                  {'scripts/ci-financial-scenario.py':'e'*64},
                  {'scripts/ci-financial-container.py':'e'*64}):
   with self.assertRaises(L.V.A.Rejected):self.identities(changes)
 def test_native_change_cannot_hide_in_separate_launcher_identity(self):
  self.identities()
  for changes in ({'Cargo.lock':'e'*64},{'new-adapter.py':'e'*64},
                  {'scripts/ci-financial-container.py':'e'*64}):
   with self.assertRaises(L.V.A.Rejected):self.identities(changes)



class TrackedAcquisitionDiagnosticTests(unittest.TestCase):
 """Real tracked main/argv/environment; only the HTTP boundary is controlled."""
 def setUp(self):
  import shutil,subprocess,sys
  from test_option import Tests
  self.fixture=Tests();self.fixture.setUp();self.addCleanup(self.fixture.doCleanups)
  self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup)
  self.root=pathlib.Path(self.temp.name);self.source=self.root/'L';self.source.mkdir()
  here=pathlib.Path(__file__).resolve().parent
  for name in L.HELPERS:shutil.copy2(here/name,self.source/name)
  shutil.copytree(here/'cleanup_snapshot',self.source/'cleanup_snapshot')
  self.job=dict(id=L.V.JOB_ID,run_id=L.V.PRODUCER['run_id'],name='synthetic-only',status='completed',conclusion='failure',steps=[dict(name=n,status='completed',conclusion='success') for n in ('Preserve exact credential-free compiled financial bundle','Verify financial containers, temporary images and build cache removed')])
  self.bodies=dict(run=self.fixture.run,job=self.job,artifact=self.fixture.artifact)
  self.plan=AdapterTests.plan(self);self.plan['artifact_pins']=self.fixture.pins
  self.plan['api_pins']={k:L.V.A.canonical(v) for k,v in self.bodies.items()}
  self.plan['api_pins']={k:__import__('hashlib').sha256(v).hexdigest() for k,v in self.plan['api_pins'].items()}
  # Test-only tracked L substitutes synthetic artifact/API constants. Real
  # candidate pins are separately exercised against the actual preserved ZIP.
  vf=self.source/'verify_option.py';code=vf.read_text()
  code=code.replace('ARTIFACT_PINS='+repr(L.V.ARTIFACT_PINS),'ARTIFACT_PINS='+repr(self.plan['artifact_pins']))
  code=code.replace('API_PINS='+repr(L.V.API_PINS),'API_PINS='+repr(self.plan['api_pins']))
  vf.write_text(code)
  (self.source/'plan.json').write_bytes(L.V.A.canonical(self.plan));(self.source/'plan.json').chmod(0o644)
  def git(*args):return subprocess.check_output(['git','-C',str(self.source),*args],stderr=subprocess.DEVNULL).decode().strip()
  git('init');git('add','.');git('-c','user.name=Tests','-c','user.email=test@example.invalid','commit','-m','tracked acquisition fixture')
  sha=git('rev-parse','HEAD')
  spec=importlib.util.spec_from_file_location('tracked_acquire_diagnostic_test',self.source/'launch_adapter.py')
  self.launcher=importlib.util.module_from_spec(spec);sys.modules[spec.name]=self.launcher;spec.loader.exec_module(self.launcher)
  from test_setup import ENV
  self.env={**ENV,'GITHUB_SHA':sha,'RUNNER_TEMP':str(self.root),'FINANCIAL_ARTIFACT_READ_TOKEN':'DO_NOT_LEAK_TOKEN'}
 def exercise(self,case):
  import urllib.request,urllib.error
  target=self.root/('wholepact-financial-reuse-download-'+case);output=io.StringIO();owner=self
  requested=[]
  secret='DO_NOT_LEAK_BODY https://secret.invalid/private?signature=DO_NOT_LEAK_URL'
  class API:
   def open(self,request,timeout):
    url=request.full_url;requested.append(url)
    if case=='http':raise urllib.error.HTTPError(url,403,secret,{'Secret':secret},io.BytesIO(secret.encode()))
    if '/artifacts?per_page=100&page=' in url:
     value=owner.bodies['artifact']
     if case=='pin_artifact':value={**value,'hostile_body':secret}
     if case=='projected_artifact':value={k:v for k,v in value.items() if k!='node_id'}
     if case=='wrong_name':value={**value,'name':'wrong'}
     if case=='wrong_run':value={**value,'workflow_run':{**value['workflow_run'],'id':1}}
     if case=='wrong_sha':value={**value,'workflow_run':{**value['workflow_run'],'head_sha':'a'*40}}
     if case=='expired':value={**value,'expired':True}
     if case=='wrong_digest':value={**value,'digest':'sha256:'+'0'*64}
     if case=='bool_id':value={**value,'id':True}
     rows=[] if case=='missing' else [value,value] if case=='duplicate' else [value]
     envelope=dict(total_count=len(rows),artifacts=rows)
     if case=='incomplete':envelope['total_count']=2
     if case=='bool_count':envelope['total_count']=True
     if case=='pagination':envelope=dict(total_count=101,artifacts=[{'id':1000+i} for i in range(100)] if url.endswith('page=1') else [value])
     return io.BytesIO(L.V.A.canonical(envelope))
    for suffix,key in [('runs/'+str(L.V.PRODUCER['run_id']),'run'),('jobs/'+str(L.V.JOB_ID),'job'),('artifacts/'+str(owner.fixture.pins['artifact_id']),'artifact')]:
     if url.endswith('/'+suffix):
      if case=='size':return io.BytesIO(b'x'*(8*1024*1024+1))
      value=owner.bodies[key]
      if case=='pin_'+key:value={**value,'hostile_body':secret}
      return io.BytesIO(L.V.A.canonical(value))
    if url.endswith('/zip'):
     location='http://secret.invalid/DO_NOT_LEAK_URL' if case=='redirect' else 'https://recorded.blob.core.windows.net/fixture.zip'
     raise urllib.error.HTTPError(url,302,secret,{'Location':location},None)
    owner.assertFalse(request.has_header('Authorization'))
    return io.BytesIO(b'bad archive '+secret.encode() if case=='digest' else owner.fixture.archive.read_bytes())
  args=[str(self.source/'launch_adapter.py'),'acquire',str(self.source/'plan.json'),str(target),str(self.source)]
  with patch.dict(os.environ,self.env,clear=True),patch.object(self.launcher.sys,'argv',args),patch('urllib.request.build_opener',return_value=API()),contextlib.redirect_stdout(output):
   if case=='deadline':
    with patch('time.monotonic',side_effect=[0,301]):
     with self.assertRaises(Exception):self.launcher.main()
   elif case in ('success','pagination'):self.assertEqual(self.launcher.main(),0)
   else:
    with self.assertRaises(Exception):self.launcher.main()
  raw=output.getvalue()
  for forbidden in ('DO_NOT_LEAK','secret.invalid','signature=','Authorization'):self.assertNotIn(forbidden,raw)
  if case in ('success','pagination'):
   self.assertNotIn('ACQUISITION_DIAGNOSTIC',raw);self.assertIn('"verified":true',raw);self.assertTrue(target.exists())
   base='https://api.github.com/repos/stanleykosi/pactloom/actions/'
   expected_urls=[base+'runs/'+str(L.V.PRODUCER['run_id']),base+'jobs/'+str(L.V.JOB_ID),base+'runs/'+str(L.V.PRODUCER['run_id'])+'/artifacts?per_page=100&page=1']
   if case=='pagination':expected_urls.append(base+'runs/'+str(L.V.PRODUCER['run_id'])+'/artifacts?per_page=100&page=2')
   expected_urls.extend([base+'artifacts/'+str(owner.fixture.pins['artifact_id'])+'/zip','https://recorded.blob.core.windows.net/fixture.zip'])
   self.assertEqual(requested,expected_urls);return
  self.assertFalse(target.exists())
  lines=[line for line in raw.splitlines() if line.startswith('CI_FINANCIAL_REUSE_ACQUISITION_DIAGNOSTIC ')]
  self.assertEqual(len(lines),1);value=json.loads(lines[0].split(' ',1)[1])
  self.assertEqual(set(value),{'version','stage','category','api_pin','http_status'})
  expected={'http':('api_run','http',403),'redirect':('archive_redirect','archive_redirect',302),'size':('api_run','download_size',0),'deadline':('api_run','download_deadline',0),'digest':('archive_verify','archive_digest',0)}
  for item in ('missing','duplicate'):expected[item]=('api_artifact','artifact_selection',0)
  for item in ('bool_id','incomplete','bool_count'):expected[item]=('api_artifact','artifact_list',0)
  for item in ('wrong_name','wrong_run','wrong_sha','expired','wrong_digest'):expected[item]=('api_artifact','artifact_origin',0)
  if case=='projected_artifact':self.assertEqual((value['stage'],value['category'],value['api_pin']),('api_artifact','api_pin','artifact'))
  elif case.startswith('pin_'):self.assertEqual((value['stage'],value['category'],value['api_pin'],value['http_status']),('api_'+case[4:],'api_pin',case[4:],0))
  else:self.assertEqual((value['stage'],value['category'],value['http_status']),expected[case]);self.assertEqual(value['api_pin'],'none')
 def test_tracked_main_failure_paths_and_secret_noninterference(self):
  for case in ('http','pin_run','pin_job','pin_artifact','redirect','size','deadline','digest'):
   with self.subTest(case=case):self.exercise(case)
 def test_tracked_main_success_has_no_failure_diagnostic_after_failures(self):
  self.exercise('http');self.exercise('success')

 def test_failed_diagnostic_output_cannot_skip_owned_staging_cleanup(self):
  import urllib.error
  target=self.root/'wholepact-financial-reuse-download-broken-output'
  class BrokenOutput:
   def write(self,*args):raise BrokenPipeError('DO_NOT_LEAK_DIAGNOSTIC_FAILURE')
   def flush(self):raise OSError('DO_NOT_LEAK_FLUSH_FAILURE')
  api=__import__('unittest.mock',fromlist=['Mock']).Mock()
  api.open.side_effect=urllib.error.HTTPError('https://secret.invalid',403,'DO_NOT_LEAK',{},None)
  args=[str(self.source/'launch_adapter.py'),'acquire',str(self.source/'plan.json'),str(target),str(self.source)]
  with patch.dict(os.environ,self.env,clear=True),patch.object(self.launcher.sys,'argv',args),patch('urllib.request.build_opener',return_value=api),contextlib.redirect_stdout(BrokenOutput()):
   with self.assertRaises(urllib.error.HTTPError):self.launcher.main()
  self.assertFalse(target.exists())
 def test_preexisting_staging_is_not_owned_or_removed(self):
  target=self.root/'wholepact-financial-reuse-download-existing';target.mkdir();marker=target/'keep';marker.write_text('owned elsewhere')
  args=[str(self.source/'launch_adapter.py'),'acquire',str(self.source/'plan.json'),str(target),str(self.source)]
  output=io.StringIO()
  with patch.dict(os.environ,self.env,clear=True),patch.object(self.launcher.sys,'argv',args),patch('urllib.request.build_opener') as network,contextlib.redirect_stdout(output):
   with self.assertRaises(FileExistsError):self.launcher.main()
   network.assert_not_called()
  self.assertEqual(marker.read_text(),'owned elsewhere')
  value=json.loads(output.getvalue().split(' ',1)[1]);self.assertEqual((value['stage'],value['category']),('directory','internal'))

 def test_raw_metadata_retains_node_id_and_projected_metadata_is_rejected(self):
  self.exercise('projected_artifact');self.exercise('success')
 def test_list_selection_rejects_missing_duplicate_malformed_and_wrong_provenance(self):
  for case in ('missing','duplicate','bool_id','incomplete','bool_count','wrong_name','wrong_run','wrong_sha','expired','wrong_digest'):
   with self.subTest(case=case):self.exercise(case)
 def test_complete_pagination_selects_pinned_artifact_and_preserves_archive_endpoint(self):
  self.exercise('pagination')

if __name__=='__main__':unittest.main()
