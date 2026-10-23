"""Pure staging tests: no network, Docker, native execution, or sockets."""
import ast
import importlib.util
import pathlib
import tempfile
import unittest
from unittest.mock import patch
HERE=pathlib.Path(__file__).resolve().parent
spec=importlib.util.spec_from_file_location('preparation_image_test',HERE/'preparation_image.py');P=importlib.util.module_from_spec(spec);spec.loader.exec_module(P)
SOURCE=HERE.parent.parent
class ImageTests(unittest.TestCase):
 def test_pinned_helpers_and_no_compilation(self):
  B,O=P.modules(SOURCE);s=P.installer(B);ast.parse(s)
  for forbidden in ('def build_module','def finalize','subprocess.run(','gcc -','symlink_to(\'/run/ci-account'):
   self.assertNotIn(forbidden,s)
  self.assertIn("sys.argv[1] == 'runtime'",s)
  self.assertIn("'--no-download'",s);self.assertIn("'--no-upgrade'",s)
  self.assertIn('wholepact-ci:x:10001:10001::/tmp:/usr/sbin/nologin',s)
  self.assertIn("strip_file_privileges()",s)
 def test_exact_docker_interface(self):
  B,_=P.modules(SOURCE);s=P.dockerfile(B.BASE_IMAGE)
  self.assertEqual(s.count('FROM '),1);self.assertIn(' AS runtime\n',s)
  self.assertIn('USER 10001:10001\n',s);self.assertIn('WORKDIR /opt/ci-financial',s)
  self.assertIn('CARGO_TARGET_DIR=/opt/ci-financial TMPDIR=/tmp HOME=/tmp',s)
  self.assertNotIn('GITHUB_STEP_SUMMARY',s);self.assertNotIn('cargo',s);self.assertNotIn('weston',s)
  import json
  self.assertEqual(json.loads(s.split('ENTRYPOINT ')[1]),P.ENTRY)
 def test_wrong_source_and_digest_before_staging(self):
  with tempfile.TemporaryDirectory() as d:
   out=pathlib.Path(d)/'out';bad=pathlib.Path(d)/'bad';bad.write_bytes(b'bad')
   with self.assertRaises(ValueError):P.build_context(out,SOURCE,'0'*40,bad)
   self.assertFalse(out.exists())
   with self.assertRaises(ValueError):P.build_context(out,SOURCE,P.SOURCE,bad)
   self.assertFalse(out.exists())
   link=pathlib.Path(d)/'link';link.symlink_to(bad)
   with self.assertRaises(ValueError):P.read(link,'pristine-setup')
 def test_runtime_only_staging_offline_install(self):
  B,O=P.modules(SOURCE);original=P.read;calls=[]
  def read(path,name):return b'ELF fixture' if name=='pristine-setup' else original(path,name)
  def download(record,stream,deadline):calls.append(record);stream.write(b'pinned-package-test-double')
  with tempfile.TemporaryDirectory() as d,patch.object(P,'modules',return_value=(B,O)),patch.object(P,'read',side_effect=read),patch.object(B,'_download',side_effect=download):
   out=pathlib.Path(d)/'out';events=[];meta=P.build_context(out,SOURCE,P.SOURCE,pathlib.Path(d)/'setup',progress=events.append)
   self.assertEqual(events,['context_inputs','context_manifest','context_download','context_write'])
   self.assertEqual(set(meta['packages']),{'runtime'})
   self.assertEqual(set(meta['inputs']),{'ci-synthetic-output.py','pristine-setup'})
   self.assertEqual({r['name'] for r in calls},{r['name'] for r in meta['packages']['runtime']})
   self.assertFalse({'gcc','cpp','libweston-14-dev','libc6-dev','pkgconf'} & set(meta['runtime']))
   self.assertEqual({p.name for p in out.iterdir()},{'packages','inputs','image-build','Dockerfile','.dockerignore'})
   self.assertFalse((out/'headers').exists());self.assertIn('openssl',meta['runtime'])
   with self.assertRaises(Exception):P.build_context(out,SOURCE,P.SOURCE,pathlib.Path(d)/'setup')
 def test_failure_checkpoint_and_formatter_failure_preserve_rejection(self):
  with tempfile.TemporaryDirectory() as d:
   out=pathlib.Path(d)/'out';events=[]
   with self.assertRaises(ValueError):P.build_context(out,SOURCE,'0'*40,out,progress=events.append)
   self.assertEqual(events,['context_inputs']);self.assertFalse(out.exists())
   def broken(stage):raise OSError('diagnostic unavailable')
   with self.assertRaisesRegex(ValueError,'^preparation_image$'):P.build_context(out,SOURCE,'0'*40,out,progress=broken)
 def test_generated_installer_main_real_private_filesystem_mocked_packages(self):
  # Execute generated main, not just syntax checks. No package tools/native
  # commands run; all absolute filesystem paths resolve beneath this temp root.
  import hashlib,json,types,sys
  B,_=P.modules(SOURCE);ns={};exec(P.installer(B).rsplit('sys.exit(execute())',1)[0],ns)
  with tempfile.TemporaryDirectory() as d:
   root=pathlib.Path(d)
   def mapped(value):
    p=pathlib.Path(value);return root/str(p).lstrip('/') if p.is_absolute() else p
   for name in ('ci-build','ci-inputs','ci-packages','etc','usr/sbin'):(root/name).mkdir(parents=True,exist_ok=True)
   (root/'etc/passwd').write_text('root:x:0:0:root:/root:/bin/sh\n')
   (root/'etc/group').write_text('root:x:0:\n')
   pins={}
   for name,raw in (('pristine-setup',b'not executed'),('ci-synthetic-output.py',b'not executed either')):
    (root/'ci-inputs'/name).write_bytes(raw);pins[name]={'size':len(raw),'sha256':hashlib.sha256(raw).hexdigest()}
   meta={'base':{},'runtime':{},'packages':{'runtime':[]},'inputs':pins}
   (root/'ci-build/metadata.json').write_text(json.dumps(meta));commands=[];owners=[]
   def checked(args,capture=False):commands.append(args);return b''
   ns.update(pathlib=types.SimpleNamespace(Path=mapped,PurePosixPath=pathlib.PurePosixPath),
     ROOT=root/'opt/ci-financial',installed=lambda:{},checked=checked,
     processes=lambda:set(),stage_archives=lambda *a:None,strip_file_privileges=lambda:None,
     sys=types.SimpleNamespace(argv=['install.py','runtime']))
   with patch.object(ns['os'],'chown',side_effect=lambda *a:owners.append(a)):ns['main']()
   self.assertIn('wholepact-ci:x:10001:10001::/tmp:/usr/sbin/nologin',(root/'etc/passwd').read_text())
   self.assertFalse((root/'etc/passwd').is_symlink())
   self.assertEqual((root/'opt/ci-financial/pristine-setup').stat().st_mode & 0o777,0o555)
   self.assertEqual({p.name:(uid,gid) for p,uid,gid in owners},{'pristine-setup':(10001,10001),'ci-synthetic-output.py':(0,0)})
   self.assertEqual(len([a for a in commands if a[0]=='apt-get']),1)
 def test_shell_run_reaps_exited_orphans_but_keeps_live_identity_guard(self):
  # Process-local subreaper is a PID1 adoption surrogate, NOT Docker evidence.
  # Disposable probe owns/reaps every descendant; no sockets/native/package tools.
  import subprocess,sys,json,textwrap
  B,_=P.modules(SOURCE)
  tree=ast.parse(B._INSTALL_SCRIPT)
  process_source=ast.get_source_segment(B._INSTALL_SCRIPT,next(n for n in tree.body if isinstance(n,ast.FunctionDef) and n.name=='processes'))
  self.assertIn(process_source,P.installer(B))
  self.assertIn("need(processes() <= before_processes, 'service_process')",P.installer(B))
  self.assertIn('RUN --network=none python3 -I -B /ci-build/install.py runtime\n',P.dockerfile(B.BASE_IMAGE))
  body=r'''
import json,os,pathlib,subprocess,sys,time,tempfile
exec(sys.argv[2])
helper=r"""
import os,pathlib,time
p=os.fork()
if p:
 print(p,flush=True);os._exit(0)
os.close(1);os.close(2)
if os.environ['PROBE_MODE']=='live':
 pathlib.Path(os.environ['PROBE_READY']).touch()
 deadline=time.monotonic()+3
 while not pathlib.Path(os.environ['PROBE_RELEASE']).exists():
  if time.monotonic()>=deadline:os._exit(17)
  time.sleep(.005)
os._exit(0)
"""
with tempfile.TemporaryDirectory() as directory:
 ready=pathlib.Path(directory)/'ready';release=pathlib.Path(directory)/'release'
 before=processes()
 env=dict(os.environ,PROBE_MODE=sys.argv[1],PROBE_READY=str(ready),PROBE_RELEASE=str(release))
 p=subprocess.run([sys.executable,'-I','-B','-c',helper],env=env,capture_output=True,check=True)
 pid=int(p.stdout);path=pathlib.Path('/proc')/str(pid)/'stat'
 def state():
  try:return path.read_text().rpartition(') ')[2].split()[0]
  except FileNotFoundError:return 'absent'
 deadline=time.monotonic()+2
 expected_exit='Z' if sys.argv[3]=='direct' else 'absent'
 while ((not ready.exists()) if sys.argv[1]=='live' else state()!=expected_exit):
  if time.monotonic()>=deadline:raise RuntimeError('test observation deadline')
  time.sleep(.005)
 observed=state();after=processes();added=any(p==str(pid) for p,start in after-before)
 release.touch()
 while state()!=expected_exit:
  if time.monotonic()>=deadline:raise RuntimeError('test child exit deadline')
  time.sleep(.005)
 try:os.waitpid(pid,0)
 except ChildProcessError:pass
 print(json.dumps({'added':added,'state':observed}),flush=True)
'''
  driver=r'''
import ctypes,json,os,shlex,subprocess,sys
libc=ctypes.CDLL(None,use_errno=True)
def adopt():
 if libc.prctl(36,1,0,0,0)!=0:raise RuntimeError('subreaper unavailable')
adopt()
results={}
for mode in ('direct','shell'):
 for state in ('exited','live'):
  args=[sys.executable,'-I','-B','-c',sys.argv[1],state,sys.argv[2],mode]
  if mode=='shell':args=['/bin/sh','-c',shlex.join(args)]
  result=subprocess.run(args,preexec_fn=adopt,capture_output=True,timeout=5,check=True)
  results[mode+'_'+state]=json.loads(result.stdout)
  while True:
   try:
    pid,status=os.waitpid(-1,os.WNOHANG)
    if pid==0:raise RuntimeError('live descendant retained')
   except ChildProcessError:break
print(json.dumps(results))
'''
  result=subprocess.run([sys.executable,'-I','-B','-c',driver,body,process_source],capture_output=True,timeout=20,check=True)
  rows=json.loads(result.stdout)
  self.assertEqual(rows['direct_exited'],{'added':True,'state':'Z'})
  self.assertEqual(rows['shell_exited'],{'added':False,'state':'absent'})
  for mode in ('direct','shell'):
   self.assertTrue(rows[mode+'_live']['added']);self.assertNotEqual(rows[mode+'_live']['state'],'Z')
 def test_shell_run_preserves_failure_status_and_identity_rejects_reuse(self):
  import subprocess,sys,shlex
  result=subprocess.run(['/bin/sh','-c',shlex.join([sys.executable,'-I','-B','-c','raise SystemExit(23)'])],capture_output=True,timeout=5)
  self.assertEqual(result.returncode,23)
  before={('1','10'),('7','20')}
  self.assertFalse({('1','10'),('7','21')}<=before) # reused PID is not old owner
  self.assertFalse({('1','10'),('7','20'),('8','22')}<=before)

if __name__=='__main__':unittest.main()

