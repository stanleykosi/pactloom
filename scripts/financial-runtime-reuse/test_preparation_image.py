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
   out=pathlib.Path(d)/'out';meta=P.build_context(out,SOURCE,P.SOURCE,pathlib.Path(d)/'setup')
   self.assertEqual(set(meta['packages']),{'runtime'})
   self.assertEqual(set(meta['inputs']),{'ci-synthetic-output.py','pristine-setup'})
   self.assertEqual({r['name'] for r in calls},{r['name'] for r in meta['packages']['runtime']})
   self.assertFalse({'gcc','cpp','libweston-14-dev','libc6-dev','pkgconf'} & set(meta['runtime']))
   self.assertEqual({p.name for p in out.iterdir()},{'packages','inputs','image-build','Dockerfile','.dockerignore'})
   self.assertFalse((out/'headers').exists());self.assertIn('openssl',meta['runtime'])
   with self.assertRaises(Exception):P.build_context(out,SOURCE,P.SOURCE,pathlib.Path(d)/'setup')
if __name__=='__main__':unittest.main()
