import contextlib
import importlib.util
import io
import os
import pathlib
import py_compile
import shutil
import tempfile
import unittest
from unittest.mock import patch,Mock
from test_setup import L,V,ROOT,ENV,TRUSTED,SHA

class BootstrapTests(unittest.TestCase):
 def setUp(self):
  self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup)
 def test_ignored_plan_cannot_change_pins_without_launcher_change(self):
  ignored=ROOT/'private';ignored.mkdir(exist_ok=True);self.addCleanup(shutil.rmtree,ignored)
  plan=ignored/'plan.json';plan.write_text('{"harness":"substituted","artifact_pins":"substituted"}')
  with patch.dict(os.environ,ENV,clear=True):
   self.assertEqual(L.git_at(ROOT,'rev-parse','HEAD').strip().decode(),SHA)
   self.assertEqual(L.git_at(ROOT,'status','--porcelain'),b'')
   with self.assertRaises(L.BootstrapRejected):L.bootstrap(ROOT,plan)
 def test_untracked_helper_is_rejected_before_execution(self):
  ignored=ROOT/'private';ignored.mkdir(exist_ok=True);self.addCleanup(shutil.rmtree,ignored)
  marker=pathlib.Path(self.temp.name)/'executed';helper=ignored/'helper.py'
  helper.write_text('from pathlib import Path\nPath('+repr(str(marker))+').write_text("bad")\n')
  with self.assertRaises(L.BootstrapRejected):TRUSTED.module('untrusted',helper)
  self.assertFalse(marker.exists())
 def test_modified_tracked_content_and_mode_rejected(self):
  tracked=ROOT/'.gitignore';original=tracked.read_bytes();mode=tracked.stat().st_mode&0o777
  try:
   tracked.write_bytes(original+b'changed\n')
   with self.assertRaises(L.BootstrapRejected):TRUSTED.tracked(tracked)
   tracked.write_bytes(original);tracked.chmod(0o755 if mode==0o644 else 0o644)
   with self.assertRaises(L.BootstrapRejected):TRUSTED.tracked(tracked)
  finally:tracked.write_bytes(original);tracked.chmod(mode)
 def test_stale_ignored_bytecode_never_executes(self):
  source=ROOT/'producer_artifacts.py';marker=pathlib.Path(self.temp.name)/'executed'
  evil=pathlib.Path(self.temp.name)/'evil.py'
  payload=('from pathlib import Path\nPath('+repr(str(marker))+').write_text("bad")\n').encode()
  evil.write_bytes(payload+b' '*(source.stat().st_size-len(payload)))
  os.utime(evil,(source.stat().st_atime,source.stat().st_mtime))
  cache=pathlib.Path(importlib.util.cache_from_source(str(source)));cache.parent.mkdir(exist_ok=True)
  self.addCleanup(shutil.rmtree,cache.parent)
  py_compile.compile(str(evil),cfile=str(cache),doraise=True)
  module=TRUSTED.module('source_only_parser',source)
  self.assertEqual(module.REPOSITORY,'stanleykosi/pactloom');self.assertFalse(marker.exists())
  # Normal P/H/L execution source inventory also refuses ignored caches rather
  # than allowing H's unchanged importlib helpers to load them.
  with self.assertRaises(V.A.Rejected):V.inventory_checkout(ROOT,SHA)
 def test_dirty_or_missing_native_sources_do_not_block_cleanup_mode(self):
  with patch.dict(os.environ,ENV,clear=True),patch.object(L.sys,'argv',['adapter','cleanup',str(ROOT)]), \
   patch.object(L,'verify_sources',side_effect=AssertionError('must not inspect P/H')) as sources, \
   patch.object(L,'load_helpers',side_effect=AssertionError('must not load run helpers')) as helpers, \
   patch.object(L,'load_supervisor',side_effect=AssertionError('must not load H')) as supervisor, \
   patch.object(L,'trusted_cleanup',return_value=True) as cleanup:
   self.assertEqual(L.main(),0);cleanup.assert_called_once();sources.assert_not_called();helpers.assert_not_called();supervisor.assert_not_called()
 def test_ignored_plan_preflight_failure_still_reaches_trusted_cleanup(self):
  ignored=ROOT/'private';ignored.mkdir(exist_ok=True);self.addCleanup(shutil.rmtree,ignored)
  plan=ignored/'plan.json';plan.write_text('{}')
  args=['adapter','run',str(plan),'/missing-P','/missing-H','/staging',str(ROOT)]
  with patch.dict(os.environ,ENV,clear=True),patch.object(L.sys,'argv',args), \
   patch.object(L,'trusted_cleanup',return_value=True) as cleanup,contextlib.redirect_stdout(io.StringIO()):
   self.assertEqual(L.main(),1);cleanup.assert_called_once()
 def test_source_failure_still_reaches_trusted_cleanup(self):
  args=['adapter','run',str(ROOT/'.gitignore'),'/missing-P','/missing-H','/staging',str(ROOT)]
  with patch.dict(os.environ,ENV,clear=True),patch.object(L.sys,'argv',args), \
   patch.object(L,'validate_plan',return_value={}),patch.object(L.json,'loads',return_value={}), \
   patch.object(L,'verify_sources',side_effect=RuntimeError('dirty missing source')), \
   patch.object(L,'trusted_cleanup',return_value=True) as cleanup,contextlib.redirect_stdout(io.StringIO()):
   self.assertEqual(L.main(),1);cleanup.assert_called_once()
 def test_changed_helper_refused_before_exec_and_failure_still_cleans(self):
  helper=ROOT/'verify_option.py';original=helper.read_bytes();marker=pathlib.Path(self.temp.name)/'helper-executed'
  try:
   helper.write_bytes(('from pathlib import Path\nPath('+repr(str(marker))+').write_text("bad")\n').encode())
   args=['adapter','run',str(ROOT/'.gitignore'),'/missing-P','/missing-H','/staging',str(ROOT)]
   with patch.dict(os.environ,ENV,clear=True),patch.object(L.sys,'argv',args), \
    patch.object(L,'trusted_cleanup',return_value=True) as cleanup,contextlib.redirect_stdout(io.StringIO()):
    self.assertEqual(L.main(),1);cleanup.assert_called_once()
   self.assertFalse(marker.exists())
  finally:helper.write_bytes(original)
 def test_cleanup_rejects_wrong_job_or_launcher_head(self):
  for change in ({'GITHUB_JOB':'other'},{'GITHUB_SHA':'f'*40}):
   with patch.dict(os.environ,{**ENV,**change},clear=True), \
    patch.object(L.sys,'argv',['adapter','cleanup',str(ROOT)]), \
    patch.object(L,'trusted_cleanup') as cleanup:
    with self.assertRaises(L.BootstrapRejected):L.main()
    cleanup.assert_not_called()

 def test_completed_owned_run_has_no_late_secondary_cleanup(self):
  args=['adapter','run',str(ROOT/'.gitignore'),'/P','/H','/staging',str(ROOT)]
  supervisor=Mock();supervisor.context.return_value=(SHA,'token')
  plan={'harness':{'source':'c'*40}}
  owned=pathlib.Path(self.temp.name)/'owned';owned.mkdir()
  with patch.dict(os.environ,ENV,clear=True),patch.object(L.sys,'argv',args), \
   patch.object(L.json,'loads',return_value={}),patch.object(L,'validate_plan',return_value=plan), \
   patch.object(L,'verify_sources',return_value=({}, {},{'source':SHA})), \
   patch.object(L.os,'chdir'),patch.object(L,'load_supervisor',return_value=supervisor), \
   patch.object(L.tempfile,'mkdtemp',return_value=str(owned)),patch.object(L.signal,'signal'), \
   patch.object(L,'run_owned',return_value=0),patch.object(L,'trusted_cleanup') as cleanup:
   self.assertEqual(L.main(),0);cleanup.assert_not_called()

 def test_cleanup_snapshot_executes_only_verified_source_without_token_or_h(self):
  real_popen=L.subprocess.Popen
  seen={};child=Mock();child.communicate.return_value=(b'',None);child.returncode=0
  def start(command,**kw):
   if command[0]=='git':return real_popen(command,**kw)
   seen.update(command=command,kw=kw)
   snapshot=pathlib.Path(kw['cwd']);self.assertFalse((snapshot/'__pycache__').exists())
   files={str(p.relative_to(snapshot)) for p in snapshot.rglob('*') if p.is_file()}
   self.assertEqual(files,{str(pathlib.Path(k).relative_to('cleanup_snapshot')) for k in L.CLEANUP_PINS})
   self.assertEqual(command[-1],'cleanup');self.assertIn('-I',command);self.assertIn('-B',command)
   self.assertNotIn('FINANCIAL_ARTIFACT_READ_TOKEN',kw['env']);return child
  with patch.dict(os.environ,{**ENV,'FINANCIAL_ARTIFACT_READ_TOKEN':'fabricated'},clear=True), \
   patch.object(L.subprocess,'Popen',side_effect=start):
   self.assertTrue(L.trusted_cleanup(TRUSTED))
  child.communicate.assert_called_once_with()
  self.assertFalse(pathlib.Path(seen['kw']['cwd']).exists())

if __name__=='__main__':unittest.main()
