#!/usr/bin/env python3
"""Fixed P81 binaries + exact H83 Python harness; never a general build cache.

P is the native producer, H is the independently reviewed runtime harness, and
L is this exact CI event checkout. Nothing rewrites or relaxes the same-job or
historical P40 routes. Imports are inert: no network, fixture or subprocess.
"""
import datetime
import hashlib
import json
import os
import pathlib
import platform
import re
import selectors
import shutil
import signal
import stat
import subprocess
import sys
import tarfile
import tempfile
import time
import types
import urllib.error
import urllib.parse
import urllib.request
import zipfile

HERE=pathlib.Path(__file__).resolve().parent
ROOT=HERE.parent
MODE=b'financial-semantic-p81-reuse\n'
PROFILE='coordinated-financial-rendered-host-semantic-v1'
PRODUCER={'repository': 'stanleykosi/pactloom', 'source': '1fa2cec1dffd8672a107327de3046110d9fb4065', 'source_tree': 'ce229516a36935787d0e0342ea0a0ba789fe3416', 'run_id': 40279157236, 'attempt': 1}
# Independently published Python-only H83 harness; native producer remains exact P81.
HARNESS={'repository': 'stanleykosi/pactloom', 'source': '8d9c7c9674f1d35d251f3c6f324917d40f176ce8', 'source_tree': '9b11431b0a0cae4a2909fdcc3dfe20b81757bc12'}
JOB_ID=121428360461
EXPIRES_AT='2026-10-27T06:52:20Z'
INVENTORY_SHA='8c41320cd51dfd719c326e5f3ef1dd823a9cf769149e177f0ab9aecf1fb939bd'
# Inventory hashes bind the Git mode: SHA256(b'100644\0' + exact reviewed bytes).
# Exact existing-path H83 mode-bound hashes; native/recipe source is unchanged.
H_CHANGES={'.github/workflows/deadline-preflight.yml': 'dab8f69c07a128a7b67c03109c54963596ff52668e973d01131003e5c7b7a4cb', 'scripts/ci-financial-flow.py': '76ee039455ea9a386052c0fcef07ba34eed3fcd47688d3c66f5ee2ac5ee2a4b9', 'scripts/financial-runtime-reuse/test_integration.py': '61c4f757319995e702571ca396e49346cc311315c78911f06a8f6f4fbaa8a900', 'scripts/tests/test_ci_financial_close_preflight.py': '08f872f028c07b28f6c4ac2d2dbbc820accb4b92b1931cfcf651e277f5426bb3', 'scripts/tests/test_ci_financial_observer.py': '0108ee849174fe753c401160b6d49fb242c530a85a2a1873ec495c394eb945c9'}
# The sole added test path has explicit raw, mode and mode-bound pins; never a glob.
H_ADDED={'scripts/tests/test_ci_financial_initial_pair_navigation.py': {'mode': '100644', 'sha256': '85b1dc64d81f572c445df1180fd6fcebb81e850fbda4ade57bbcbf62b152c5cc', 'mode_content_sha256': '4dbf7bfdb4a1f1d94b30cb8adc51a3f804fc1066a7f5c4d4f1993fb15ca1c997'}}
L_ADDED=frozenset(('scripts/ci-financial-p81-reuse.py','scripts/tests/test_ci_financial_p81_reuse.py'))
L_CHANGED=frozenset(('.github/workflows/durable-native-linux.yml','scripts/qualification-gate-mode'))
API_PINS={'run': '15045fc90e79d7c522f33b5bdc48a14f5c4928883f6f1056f97888cc6f7bdca3', 'job': '2e47e60fe2981c385c6385ff847c5e6025c2356add0f4d1949822a3fdcbb4a2e', 'artifact': '50474f359fe2eb2aa0db0f819755944e8accadf7fcda008b27f42decdba9abe1'}
PINS={'artifact_id': 12632736595, 'archive_size': 122508785, 'archive_sha256': '84e1cd67254238eb9c24df4f76b24c6c3c6b9aa817565575e9aa41a00fd51efa', 'bundle_size': 355614720, 'bundle_sha256': '97d7e9a96d72057428930684f00e6b0c6701e7ed2e80c6f29ef8744cfdc6a2c4'}
ELF_PINS={'coordinator-observed': {'sha256': 'da92f2e9c3ab4313ba905bedfc2d79e6a6be117141f4e03f8f9fb2cda393e44b', 'size': 100635120}, 'coordinator-production': {'sha256': 'c20a01683a7330a2eef8df2da2cea4d1dedfc06fde57649529c226ffe6933554', 'size': 99870504}, 'pristine-setup': {'sha256': 'e1a807fa1f925d05ddf6efa07c9356e56e2f0b55e45220afaa9cdcf2a1498987', 'size': 154828120}}
# Complete fixed cleanup closure: exact H83 image and current contract/supervisor.
# Nine files come from tracked L bytes;
# the tenth is the original P81 semantic gate literal, independently pinned.
# L's new activation mode never becomes P/H's native profile or source bytes.
CLEANUP_PINS={'ci-bootstrap-output.py': 'ce7c9a11b439e2a31f6e38c8401ab644840abba78c05482224484e5c931cc898', 'ci-bootstrap-supervisor.py': 'f606f43e4c3436209a380377ae7d8225fe8ee45828a748c776699f6190c709c0', 'ci-financial-artifacts.py': 'f31041a577f3fa0dc65f5880ac0a77d8fd145e53d4d576524ede3e2adbec29ce', 'ci-financial-contract.py': '9b3843894678f9ac167b3057b8c2fbf46ba86e47b7ed9c57a970386a1321e09c', 'ci-financial-external-output.py': '109dded70c7d7eca3160dd305601b3f5c9f31e24c8f0e6bb3c5161f8652c5587', 'ci-financial-image.py': '3609f2a672bd6db7e5f9edaa708877f11cff70e39be28644df0b3b50030b4633', 'ci-financial-ocr-image.py': '5dd479e0def902357714b07d1116a83f2c9ad215ea462493032502e29d564d67', 'ci-financial-supervisor.py': '12504501acd3ceff8fe0a89273f0da2be321c1e760e7e091fef8f7c5734050e4', 'ci-ui-image.py': '181ebc76e3d15d02381ac6a7338346ea333c9026630968098dc3d25ee58b551b', 'qualification-gate-mode': 'ebadd1b086ae7c27c6a731049ef4c883841e9d7a710ac4e2b444677f130b38a2'}
CI_KEYS=('PATH','RUNNER_TEMP','GITHUB_ACTIONS','RUNNER_OS','RUNNER_ENVIRONMENT',
 'GITHUB_REPOSITORY','GITHUB_REF','GITHUB_EVENT_NAME','GITHUB_SHA','GITHUB_RUN_ID','GITHUB_RUN_ATTEMPT','GITHUB_JOB')

class Rejected(Exception):pass

def require(ok,reason):
 if not ok:raise Rejected(reason)

def sha(data):return hashlib.sha256(data).hexdigest()

def canonical(value):return (json.dumps(value,sort_keys=True,separators=(',',':'),ensure_ascii=True)+'\n').encode('ascii')

def module_bytes(name,path,data):
 module=types.ModuleType(name);module.__file__=str(path);sys.modules[name]=module
 exec(compile(data,str(path),'exec'),module.__dict__);return module

# Current inert strict parser, pinned independently of any artifact's claims.
_parser=HERE/'ci-financial-artifacts.py'
_parser_bytes=_parser.read_bytes()
require(not _parser.is_symlink() and sha(_parser_bytes)==CLEANUP_PINS[_parser.name],'parser_pin')
A=module_bytes('fixed_p81_artifacts',_parser,_parser_bytes)
require(A.MANIFEST_VERSION==2 and A.recipe(PROFILE)['build_recipe_version']==3,'recipe')

def safe_environment():
 require(not any(any(w in k.upper() for w in ('TOKEN','PASSWORD','SECRET','CREDENTIAL')) for k in os.environ),'credential_environment')
 return dict(PATH=os.environ['PATH'],HOME='/nonexistent',GIT_CONFIG_NOSYSTEM='1',GIT_CONFIG_GLOBAL='/dev/null',GIT_TERMINAL_PROMPT='0')

def git_env():
 return dict(PATH=os.environ['PATH'],HOME='/nonexistent',GIT_CONFIG_NOSYSTEM='1',GIT_CONFIG_GLOBAL='/dev/null',GIT_TERMINAL_PROMPT='0')

def git(root,*args):
 return subprocess.check_output(['git','-C',str(root),*args],env=git_env(),stderr=subprocess.DEVNULL)

def event_identity():
 checks={'GITHUB_ACTIONS':'true','RUNNER_OS':'Linux','RUNNER_ENVIRONMENT':'github-hosted','GITHUB_REPOSITORY':PRODUCER['repository'],
  'GITHUB_REF':'refs/heads/qualification/durable-proposal-v1','GITHUB_EVENT_NAME':'push','GITHUB_JOB':'synthetic-only'}
 require(all(os.environ.get(k)==v for k,v in checks.items()) and platform.machine()=='x86_64','ci_context')
 commit=os.environ.get('GITHUB_SHA','');run=os.environ.get('GITHUB_RUN_ID','');attempt=os.environ.get('GITHUB_RUN_ATTEMPT','')
 require(re.fullmatch('[0-9a-f]{40}',commit) and re.fullmatch('[1-9][0-9]{0,19}',run) and re.fullmatch('[1-9][0-9]{0,5}',attempt),'ci_identity')
 return commit,run+'-'+attempt+'-'+commit

def tracked(root,commit,path):
 root=pathlib.Path(root).resolve();path=pathlib.Path(path)
 require(path.absolute()==path.resolve() and path.resolve().is_relative_to(root),'tracked_path')
 relative=path.relative_to(root).as_posix();row=git(root,'ls-tree','-z',commit,'--',relative)
 require(row.endswith(b'\0') and row.count(b'\0')==1,'tracked_path')
 fields,name=row[:-1].split(b'\t');mode,kind,oid=fields.split(b' ')
 require(name.decode()==relative and mode in (b'100644',b'100755') and kind==b'blob','tracked_kind')
 data=git(root,'cat-file','blob',oid.decode());meta=path.lstat()
 require(stat.S_ISREG(meta.st_mode) and meta.st_nlink==1 and stat.S_IMODE(meta.st_mode)==int(mode,8)&0o777 and path.read_bytes()==data,'tracked_bytes')
 return mode,data

def inventory_checkout(root,commit):
 root=pathlib.Path(root).resolve();require(A.COMMIT.fullmatch(commit) is not None,'commit')
 require(git(root,'rev-parse','HEAD').strip().decode()==commit,'checkout_commit')
 require(git(root,'status','--porcelain','--untracked-files=all')==b'','dirty_checkout')
 require(git(root,'ls-files','--others','--ignored','--exclude-standard','-z')==b'','ignored_checkout_input')
 result={}
 for row in git(root,'ls-tree','-rz','--full-tree',commit).split(b'\0'):
  if not row:continue
  fields,name=row.split(b'\t');mode,kind,oid=fields.split(b' ');name=name.decode('ascii');A.closure({name:'0'*64})
  require(name not in result and kind==b'blob' and mode in (b'100644',b'100755'),'source_kind')
  actual,data=tracked(root,commit,root/name);require(actual==mode,'source_mode');result[name]=sha(mode+b'\0'+data)
 A.closure(result)
 require(git(root,'rev-parse','HEAD').strip().decode()==commit and git(root,'status','--porcelain','--untracked-files=all')==b''
  and git(root,'ls-files','--others','--ignored','--exclude-standard','-z')==b'','source_changed')
 return git(root,'rev-parse',commit+'^{tree}').strip().decode(),result

def equivalent(producer,current):
 A.closure(producer);A.closure(current)
 require(set(producer).isdisjoint(H_ADDED),'added_harness_overlap')
 require(set(current)==set(producer)|set(H_ADDED),'tracked_path_set')
 require({n:current[n] for n in H_ADDED}=={n:p['mode_content_sha256'] for n,p in H_ADDED.items()},'unreviewed_added_harness')
 changes={n:current[n] for n in producer if producer[n]!=current[n]}
 require(changes==H_CHANGES,'unreviewed_harness_delta');return changes

def verify_added_harness(root):
 # Check all three independent pins against the same tracked regular blob.
 for name,pin in H_ADDED.items():
  mode,data=tracked(root,HARNESS['source'],pathlib.Path(root)/name)
  require(mode.decode('ascii')==pin['mode'] and sha(data)==pin['sha256']
   and sha(mode+b'\0'+data)==pin['mode_content_sha256'],'added_harness_blob')

def verify_sources(producer_root,harness_root,launcher_root,launcher_commit):
 require(A.COMMIT.fullmatch(HARNESS['source']) is not None,'unbound_harness')
 roots=[pathlib.Path(p).resolve() for p in (producer_root,harness_root,launcher_root)]
 require(len(set(roots))==3 and all(not a.is_relative_to(b) for a in roots for b in roots if a!=b),'checkout_separation')
 require(launcher_commit not in (PRODUCER['source'],HARNESS['source']),'separate_launcher')
 pt,pinv=inventory_checkout(roots[0],PRODUCER['source']);ht,hinv=inventory_checkout(roots[1],HARNESS['source']);lt,linv=inventory_checkout(roots[2],launcher_commit)
 require(pt==PRODUCER['source_tree'] and ht==HARNESS['source_tree'],'tree_identity')
 require(sha(canonical(pinv))==INVENTORY_SHA,'producer_inventory');equivalent(pinv,hinv)
 verify_added_harness(roots[1])
 require(set(linv)==set(hinv)|L_ADDED and not set(hinv)&L_ADDED,'launcher_path_set')
 require({n for n in hinv if hinv[n]!=linv[n]}==L_CHANGED,'launcher_delta')
 require((roots[2]/'scripts/qualification-gate-mode').read_bytes()==MODE,'launcher_mode')
 return pinv,hinv,dict(repository=PRODUCER['repository'],source=launcher_commit,source_tree=lt)

def verify_metadata(run,job,artifact,now=None):
 for name,value in [('run',run),('job',job),('artifact',artifact)]:
  require(type(value) is dict and sha(canonical(value))==API_PINS[name],'api_'+name)
 require(run['id']==PRODUCER['run_id'] and run['run_attempt']==1 and run['head_sha']==PRODUCER['source'] and run['head_commit']['tree_id']==PRODUCER['source_tree']
  and run['repository']['full_name']==PRODUCER['repository'] and run['repository']['id']==1421982727 and run['head_repository']['id']==1421982727
  and run['head_branch']=='qualification/durable-proposal-v1' and run['event']=='push' and run['path']=='.github/workflows/durable-native-linux.yml'
  and run['status']=='completed' and run['conclusion']=='failure','producer_run')
 require(job['id']==JOB_ID and job['run_id']==PRODUCER['run_id'] and job['run_attempt']==1 and job['head_sha']==PRODUCER['source']
  and job['name']=='synthetic-only' and job['status']=='completed' and job['conclusion']=='failure','producer_job')
 for name in ('Financial recipe and projection gates (no build or fixture)','Fresh exact-source financial build (no runtime fixture)',
              'Preserve exact credential-free compiled financial bundle','Verify financial containers, temporary images and build cache removed'):
  rows=[s for s in job['steps'] if s['name']==name];require(len(rows)==1 and rows[0]['status']=='completed' and rows[0]['conclusion']=='success','producer_step')
 require(artifact['id']==PINS['artifact_id'] and artifact['node_id']=='MDg6QXJ0aWZhY3QxMjYzMjczNjU5NQ=='
  and artifact['name']=='financial-build-40279157236-1-'+PRODUCER['source'] and artifact['expired'] is False and artifact['expires_at']==EXPIRES_AT
  and artifact['size_in_bytes']==PINS['archive_size'] and artifact['digest']=='sha256:'+PINS['archive_sha256']
  and artifact['workflow_run']==dict(id=PRODUCER['run_id'],repository_id=1421982727,head_repository_id=1421982727,head_branch='qualification/durable-proposal-v1',head_sha=PRODUCER['source']),'artifact_origin')
 now=datetime.datetime.now(datetime.timezone.utc) if now is None else now
 require(now.tzinfo is not None and now<datetime.datetime.fromisoformat(EXPIRES_AT.replace('Z','+00:00')),'expired_artifact')
 return True

def regular(path,size=None,mode=None):
 path=pathlib.Path(path);meta=path.lstat()
 require(stat.S_ISREG(meta.st_mode) and meta.st_nlink==1 and meta.st_uid==os.getuid() and (size is None or meta.st_size==size)
  and (mode is None or stat.S_IMODE(meta.st_mode)==mode),'file_kind_mode_size')
 return path

def digest(path):
 with regular(path).open('rb') as stream:return hashlib.file_digest(stream,'sha256').hexdigest()

def verify_archive(archive,bundle,producer_inventory):
 require(sha(canonical(producer_inventory))==INVENTORY_SHA,'producer_inventory')
 archive=regular(archive,PINS['archive_size']);require(digest(archive)==PINS['archive_sha256'],'archive_digest')
 bundle=pathlib.Path(bundle);require(not bundle.exists() and not bundle.is_symlink(),'fresh_bundle')
 with zipfile.ZipFile(archive) as z:
  rows=z.infolist();require(len(rows)==1 and rows[0].filename=='build.tar' and not rows[0].is_dir() and rows[0].file_size==PINS['bundle_size']
   and not rows[0].flag_bits&1,'zip_entries')
  with z.open(rows[0]) as src,bundle.open('xb') as dst:shutil.copyfileobj(src,dst)
 bundle.chmod(0o400);regular(bundle,PINS['bundle_size'],0o400);require(digest(bundle)==PINS['bundle_sha256'],'bundle_digest')
 value=A.verify_bundle(bundle,PRODUCER,producer_inventory,PROFILE)
 require(value['files']==ELF_PINS,'independent_elf_pins')
 with tarfile.open(bundle,'r:') as tar:
  for name in A.NAMES:
   member=tar.getmember(name);require(member.isfile() and member.mode==0o555,'elf_mode')
   with tar.extractfile(member) as stream:head=stream.read(64)
   require(head[:7]==b'\x7fELF\x02\x01\x01' and int.from_bytes(head[18:20],'little')==62 and int.from_bytes(head[16:18],'little') in (2,3),'elf_architecture')
 return value

def stage_artifacts(bundle,manifest,target):
 require(digest(bundle)==PINS['bundle_sha256'] and manifest['files']==ELF_PINS,'staging_digest')
 target=pathlib.Path(target);target.mkdir(mode=0o700,exist_ok=False)
 with tarfile.open(bundle,'r:') as tar:
  for name in A.NAMES:
   with tar.extractfile(name) as source,(target/name).open('xb') as destination:shutil.copyfileobj(source,destination)
   (target/name).chmod(0o555);regular(target/name,ELF_PINS[name]['size'],0o555)
   require(A.file_pin(target/name)==ELF_PINS[name],'staged_elf')
 return target

def read_json(path):
 path=regular(path);require(path.stat().st_size<=8*1024*1024,'json_size')
 raw=path.read_bytes();value=json.loads(raw,object_pairs_hook=A.pairs);require(canonical(value)==raw,'canonical_json');return value

def verified_api(staging):
 values={name:read_json(pathlib.Path(staging)/(name+'.json')) for name in API_PINS}
 verify_metadata(values['run'],values['job'],values['artifact']);return values

class NoRedirect(urllib.request.HTTPRedirectHandler):
 def redirect_request(self,*args,**kwargs):return None

def bounded_read(response,limit,deadline,destination=None):
 count=0;chunks=[]
 while True:
  require(time.monotonic()<deadline,'download_deadline');chunk=response.read(min(1024*1024,limit-count+1))
  if not chunk:break
  count+=len(chunk);require(count<=limit,'download_size')
  if destination is None:chunks.append(chunk)
  else:destination.write(chunk)
 return b''.join(chunks) if destination is None else count

def redirect_target(url):
 p=urllib.parse.urlsplit(url)
 require(p.scheme=='https' and p.port in (None,443) and p.username is None and p.password is None and not p.fragment and p.hostname is not None
  and (p.hostname.endswith('.blob.core.windows.net') or p.hostname.endswith('.actions.githubusercontent.com')),'archive_redirect')
 return url

def acquire(staging,token):
 """Only caller receiving existing actions:read token. No child/native execution."""
 require(type(token) is str and 0<len(token)<=8192 and '\n' not in token and '\r' not in token,'token')
 staging=pathlib.Path(staging);require(staging.is_dir() and not staging.is_symlink() and not any(staging.iterdir()),'fresh_acquisition')
 api=urllib.request.build_opener(NoRedirect());deadline=time.monotonic()+300
 base='https://api.github.com/repos/stanleykosi/pactloom/actions/'
 headers={'Authorization':'Bearer '+token,'Accept':'application/vnd.github+json','X-GitHub-Api-Version':'2022-11-28','User-Agent':'pactloom-fixed-p81-acquisition'}
 def get(path):
  with api.open(urllib.request.Request(base+path,headers=headers),timeout=30) as response:
   return json.loads(bounded_read(response,8*1024*1024,deadline),object_pairs_hook=A.pairs)
 run=get('runs/'+str(PRODUCER['run_id']))
 # Bind the exact collection representations independently captured for review.
 jobs=get('runs/'+str(PRODUCER['run_id'])+'/jobs?per_page=100&page=1')
 artifacts=get('runs/'+str(PRODUCER['run_id'])+'/artifacts?per_page=100&page=1')
 require(type(jobs) is dict and jobs.get('total_count')==1 and len(jobs.get('jobs',[]))==1,'job_selection')
 require(type(artifacts) is dict and artifacts.get('total_count')==1 and len(artifacts.get('artifacts',[]))==1,'artifact_selection')
 job=jobs['jobs'][0];artifact=artifacts['artifacts'][0];verify_metadata(run,job,artifact)
 for name,value in [('run',run),('job',job),('artifact',artifact)]:
  with (staging/(name+'.json')).open('xb') as f:f.write(canonical(value))
 request=urllib.request.Request(base+'artifacts/'+str(PINS['artifact_id'])+'/zip',headers=headers)
 try:
  with api.open(request,timeout=30):raise Rejected('missing_redirect')
 except urllib.error.HTTPError as response:
  require(response.code in (301,302,303,307,308),'archive_response');url=redirect_target(response.headers['Location']);response.close()
 # New request has no Authorization, cookies, Referer or token propagation.
 request=urllib.request.Request(url,headers={'User-Agent':'pactloom-fixed-p81-acquisition'})
 with api.open(request,timeout=30) as response,(staging/'producer.zip').open('xb') as destination:
  bounded_read(response,PINS['archive_size'],deadline,destination)
 require(regular(staging/'producer.zip',PINS['archive_size']) and digest(staging/'producer.zip')==PINS['archive_sha256'],'archive_digest')
 verified_api(staging)

def bootstrap(launcher):
 """Before P/H/API access, bind L event and collect all ten cleanup sources."""
 launcher=pathlib.Path(launcher).resolve();commit,token=event_identity()
 require(ROOT==launcher and git(launcher,'rev-parse','HEAD').strip().decode()==commit,'launcher_commit')
 tracked(launcher,commit,pathlib.Path(__file__));require(tracked(launcher,commit,launcher/'scripts/qualification-gate-mode')[1]==MODE,'launcher_mode')
 data={}
 for name,pin in CLEANUP_PINS.items():
  raw=b'financial-semantic\n' if name=='qualification-gate-mode' else tracked(launcher,commit,launcher/'scripts'/name)[1]
  require(sha(raw)==pin,'cleanup_pin');data[name]=raw
 require(set(data)==set(CLEANUP_PINS) and len(data)==10,'cleanup_closure')
 return commit,token,data

def cleanup_process(args,cwd,env,*,seconds=240,limit=1024*1024):
 """Bound the independent cleanup child, including a stuck inherited pipe."""
 process=subprocess.Popen(args,cwd=cwd,env=env,stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,
  stdin=subprocess.DEVNULL,start_new_session=True)
 selector=None
 try:
  selector=selectors.DefaultSelector();deadline=time.monotonic()+seconds;count=0
  selector.register(process.stdout,selectors.EVENT_READ)
  while selector.get_map():
   require(time.monotonic()<deadline,'cleanup_timeout')
   for key,_ in selector.select(min(.1,max(0,deadline-time.monotonic()))):
    data=os.read(key.fileobj.fileno(),min(65536,limit-count+1))
    if not data:selector.unregister(key.fileobj);continue
    count+=len(data);require(count<=limit,'cleanup_output')
  remaining=deadline-time.monotonic();require(remaining>0,'cleanup_timeout')
  try:return process.wait(timeout=remaining)
  except subprocess.TimeoutExpired:raise Rejected('cleanup_timeout') from None
 except BaseException:
  # Kill the owned process group even if the direct child already exited but
  # left a descendant holding the output pipe. Never log its raw output.
  try:os.killpg(process.pid,signal.SIGKILL)
  except ProcessLookupError:pass
  process.wait(timeout=10)
  raise
 finally:
  if selector is not None:selector.close()
  process.stdout.close()

def trusted_cleanup(cleanup_sources):
 """No unchecked P/H imports; snapshot bytes are independently annex-pinned."""
 require(set(cleanup_sources)==set(CLEANUP_PINS) and all(sha(cleanup_sources[n])==p for n,p in CLEANUP_PINS.items()),'cleanup_closure')
 snapshot=pathlib.Path(tempfile.mkdtemp(prefix='wholepact-financial-p81-cleanup-',dir=os.environ['RUNNER_TEMP']))
 try:
  scripts=snapshot/'scripts';scripts.mkdir(mode=0o700)
  for name,raw in cleanup_sources.items():
   (scripts/name).write_bytes(raw);(scripts/name).chmod(0o444)
  env={k:os.environ[k] for k in CI_KEYS};env.update(git_env())
  status=cleanup_process([sys.executable,'-I','-B',str(scripts/'ci-financial-supervisor.py'),'cleanup'],snapshot,env)
  # Do not forward the supervisor's generic RESULT passed/cleanup_only record:
  # cleanup-only success is not overall or runtime qualification.
  clean=status==0
  print('CI_FINANCIAL_P81_CLEANUP '+json.dumps(dict(verified=clean,runtime_verified=False),sort_keys=True,separators=(',',':')),flush=True)
  return clean
 finally:shutil.rmtree(snapshot)

def runtime_owned(S,root,inputs,launcher_identity,token):
 """Unchanged H supervisor primitives; native producer remains P, never H/L."""
 root=pathlib.Path(root);tag='wholepact-financial:'+token;passed=False;first=None
 try:
  (root/'docker').mkdir(mode=0o700);os.environ['FINANCIAL_DOCKER_CONFIG']=str(root/'docker')
  require(S.I.profile()==PROFILE and S.A.recipe(PROFILE)==A.recipe(PROFILE) and S.FEATURES==A.recipe(PROFILE)['artifact_features'],'recipe')
  S.exact_source(HARNESS['source']);S.package_preflight()
  S.emit('P81_REUSE_SOURCE',dict(native_producer=PRODUCER,runtime_harness=HARNESS,launcher=launcher_identity,
   artifact_pins=PINS,native_binaries_reused=True,native_binaries_freshly_compiled=False,
   historical_producer_build_verified=True,fresh_native_gates_run=False,qualification_profile=PROFILE,
   public_chain_verified=False,dispatch_requested=False))
  with S.PipelineStage('image') as stage:
   context=S.stage_image_context(root,inputs,HARNESS['source'])
   S.docker(['pull','--platform','linux/amd64',S.BASE],'image',seconds=300,limit=4*1024*1024)
   foundation_tag='wholepact-financial-foundation:'+token
   foundation=S.build_image(context,'foundation',foundation_tag,token,HARNESS['source'],fresh=True)
   image_id=S.final_image(context,tag,foundation_tag,token,HARNESS['source'],foundation);stage.passed=True
  with S.PipelineStage('fixture-runtime') as stage:
   S.exact_source(HARNESS['source']);_,passed=S.run_case('external',image_id,token,HARNESS['source']);stage.passed=passed
 except S.Failure as error:
  first=S.failure_record(error)
  if not getattr(error,'published',False):S.emit('FAILURE',dict(**first,cleanup_pending=True))
 except BaseException:
  first={'stage':'supervisor','check':'internal'};S.emit('FAILURE',dict(**first,cleanup_pending=True))
 finally:
  try:clean=S.cleanup(token,tag)
  except BaseException:clean=False
  try:shutil.rmtree(root)
  except OSError:clean=False
  passed=passed and clean and first is None
  S.emit('P81_REUSE_RESULT',dict(passed=passed,native_producer=PRODUCER,runtime_harness=HARNESS,launcher=launcher_identity,
   native_binaries_reused=True,native_binaries_freshly_compiled=False,profile=PROFILE,final_qualification=False,
   semantic_assisted_host_observation=True,pixel_only_ui_verified=False,
   synthetic_external_witness_flow_verified=passed,synthetic_full_native_verified=False,
   integrated_witness_services=7,retained_inert_witnesses=6,containers_and_image_removed=clean,
   public_chain_verified=False,dispatch_requested=False,deployment_verified=False))
 return 0 if passed else 1

def staging_path():
 temp=pathlib.Path(os.environ['RUNNER_TEMP']).resolve()
 return temp/('wholepact-financial-p81-download-'+os.environ['GITHUB_RUN_ID']+'-'+os.environ['GITHUB_RUN_ATTEMPT'])

def main():
 os.umask(0o077);require(len(sys.argv)>=3,'arguments')
 mode,launcher=sys.argv[1:3];require(mode in ('acquire','verify','run','cleanup'),'arguments')
 commit,token,cleanup_sources=bootstrap(launcher)
 if mode=='cleanup':
  require(len(sys.argv)==3,'arguments');safe_environment()
  return 0 if trusted_cleanup(cleanup_sources) else 1
 if mode=='acquire':
  require(len(sys.argv)==3,'arguments');credential=os.environ.pop('FINANCIAL_ARTIFACT_READ_TOKEN','');safe_environment()
  staging=staging_path();staging.mkdir(mode=0o700,exist_ok=False)
  try:acquire(staging,credential)
  except BaseException:
   try:shutil.rmtree(staging)
   except OSError:pass # Original acquisition failure remains primary; workflow cleanup always runs.
   raise
  finally:credential=''
  print('CI_FINANCIAL_P81_ACQUIRED {"verified":true,"pre_runtime":true}',flush=True);return 0
 require(len(sys.argv)==5,'arguments');safe_environment();producer,harness=sys.argv[3:5]
 root=None;owned=False
 try:
  pinv,hinv,l_identity=verify_sources(producer,harness,launcher,commit)
  staging=staging_path();meta=staging.lstat()
  require(stat.S_ISDIR(meta.st_mode) and meta.st_uid==os.getuid() and stat.S_IMODE(meta.st_mode)==0o700
   and {p.name for p in staging.iterdir()}=={'producer.zip','run.json','job.json','artifact.json'},'acquisition_directory')
  verified_api(staging)
  root=pathlib.Path(tempfile.mkdtemp(prefix='wholepact-financial-p81-',dir=os.environ['RUNNER_TEMP']))
  manifest=verify_archive(staging/'producer.zip',root/'original-build.tar',pinv)
  if mode=='verify':
   print('CI_FINANCIAL_P81_VERIFIED '+json.dumps(dict(native_producer=PRODUCER,runtime_harness=HARNESS,launcher=l_identity,
    source_and_archive_verified=True,runtime_verified=False,native_binaries_freshly_compiled=False),sort_keys=True,separators=(',',':')),flush=True)
   return 0
  os.chdir(harness)
  S=module_bytes('fixed_p81_harness_supervisor',pathlib.Path(harness)/'scripts/ci-financial-supervisor.py',
   tracked(pathlib.Path(harness),HARNESS['source'],pathlib.Path(harness)/'scripts/ci-financial-supervisor.py')[1])
  event,actual_token=S.context();require(event==commit and actual_token==token,'launcher_event')
  def interrupted(_signal,_frame):raise S.Failure('supervisor','interrupted')
  signal.signal(signal.SIGTERM,interrupted);signal.signal(signal.SIGINT,interrupted)
  for args in ([sys.executable,'-I','-B','scripts/ci-financial-launch-tests.py'],
               [sys.executable,'-I','-B','-m','unittest','discover','-s','scripts/tests','-p','test*financial*.py']):
   S.checked(args,'preflight',seconds=300,limit=1024*1024,env=safe_environment())
  verify_sources(producer,harness,launcher,commit);verified_api(staging)
  inputs=stage_artifacts(root/'original-build.tar',manifest,root/'artifacts')
  owned=True;return runtime_owned(S,root,inputs,l_identity,token)
 finally:
  if not owned:
   primary_pending=sys.exc_info()[0] is not None
   removed=True
   try:
    if root is not None:shutil.rmtree(root)
   except OSError:removed=False
   # Cleanup is reached even if private-directory removal failed. Any original
   # exception still propagates; cleanup-only success never replaces failure.
   try:clean=trusted_cleanup(cleanup_sources)
   except BaseException:clean=False
   if not (clean and removed):
    print('CI_FINANCIAL_P81_CLEANUP {"verified":false,"runtime_verified":false}',flush=True)
    if not primary_pending:raise Rejected('cleanup_unverified')

if __name__=='__main__':
 try:sys.exit(main())
 except BaseException as error:
  if isinstance(error,SystemExit):raise
  # Never leak exceptions, URLs, API bodies, credentials, paths or native output.
  print('CI_FINANCIAL_P81_PREFLIGHT {"passed":false,"runtime_verified":false,"code":"verification_failed"}',flush=True)
  sys.exit(1)
