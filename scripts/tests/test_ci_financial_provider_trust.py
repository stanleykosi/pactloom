"""Public-fixture trust custody tests; no host trust store, sockets or product run."""
import contextlib
import importlib.util
import os
import pathlib
import ssl
import stat
import subprocess
import sys
import tempfile
import time
import unittest
from unittest import mock

ROOT=pathlib.Path(__file__).resolve().parents[1]
spec=importlib.util.spec_from_file_location('provider_trust_tested',ROOT/'ci-financial-container.py')
M=importlib.util.module_from_spec(spec);sys.modules[spec.name]=M;spec.loader.exec_module(M)

class FixtureProviderTrustTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.material=tempfile.TemporaryDirectory(prefix='public-fixture-ca-')
        directory=pathlib.Path(cls.material.name)
        # Locally generated test material only; the private key is never passed
        # to the production reader/installer or copied to a trust location.
        subprocess.run(['/usr/bin/openssl','req','-new','-x509','-nodes','-newkey','ec',
            '-pkeyopt','ec_paramgen_curve:P-256','-sha256','-days','1',
            '-subj','/CN=wholepact-synthetic-public-block-root',
            '-addext','basicConstraints=critical,CA:TRUE',
            '-addext','keyUsage=critical,keyCertSign,cRLSign',
            '-keyout',str(directory/'ca.key'),'-out',str(directory/'ca.pem')],
            stdin=subprocess.DEVNULL,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,
            env={},check=True,timeout=10)
        cls.ca=(directory/'ca.pem').read_bytes()
        subprocess.run(['/usr/bin/openssl','req','-new','-x509','-key',str(directory/'ca.key'),
            '-sha256','-days','1','-subj','/CN=not-a-ca',
            '-addext','basicConstraints=critical,CA:FALSE','-out',str(directory/'leaf.pem')],
            stdin=subprocess.DEVNULL,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,
            env={},check=True,timeout=10)
        cls.leaf=(directory/'leaf.pem').read_bytes()
    @classmethod
    def tearDownClass(cls):cls.material.cleanup()

    def setUp(self):
        self.temporary=tempfile.TemporaryDirectory(prefix='provider-custody-')
        self.base=pathlib.Path(self.temporary.name)
        self.parent=self.base/'ci-fixture'/'full-parent'
        self.root=self.parent/'f-actual'
        self.tls=self.root/'synthetic-provider-tls-v1'
        for directory in (self.parent.parent,self.parent,self.root,self.tls):directory.mkdir(mode=0o700)
        self.selected=self.root/M.F.FIXTURE_FILE
        self.ca_path=self.tls/'ca.pem';self.ca_path.write_bytes(self.ca);self.ca_path.chmod(0o600)
        self.trust=self.base/'trust';self.trust.mkdir(mode=0o755);self.trust.chmod(0o755)
        self.target=self.trust/'fixture-provider-ca.pem'
        self.link=self.base/'fixture-link.pem';self.link.symlink_to(self.target)
        self.stack=contextlib.ExitStack()
        self.stack.enter_context(mock.patch.object(M.F,'ARTIFACT_PARENT',self.parent))
        self.stack.enter_context(mock.patch.object(M,'UID',os.getuid()))
        self.stack.enter_context(mock.patch.object(M,'PROVIDER_CA',self.target))
        self.stack.enter_context(mock.patch.object(M,'PROVIDER_CA_LINK',self.link))
    def tearDown(self):self.stack.close();self.temporary.cleanup()

    @contextlib.contextmanager
    def root_adapter(self):
        # Inert process/ownership adapter only: no UID change or host trust path.
        original=pathlib.Path.lstat
        def lstat(path,*args,**kwargs):
            value=original(path,*args,**kwargs)
            if path in (self.trust,self.link):
                fields=list(value);fields[4]=fields[5]=0;return os.stat_result(fields)
            return value
        with mock.patch.object(M.os,'getpid',return_value=1), \
             mock.patch.object(M.os,'getresuid',return_value=(0,0,0)), \
             mock.patch.object(M.os,'getresgid',return_value=(0,0,0)), \
             mock.patch.object(M,'fixture_effective_identity',contextlib.nullcontext), \
             mock.patch.object(pathlib.Path,'lstat',lstat):yield

    def test_exact_public_ca_read_parse_and_real_strict_verification(self):
        self.assertEqual(M.read_fixture_provider_ca(self.selected),self.ca)
        M.validate_fixture_provider_ca(self.ca)
        with self.root_adapter():M.install_fixture_provider_ca(self.selected,time.monotonic_ns()+10_000_000_000)
        self.assertEqual(self.target.read_bytes(),self.ca)
        self.assertEqual(stat.S_IMODE(self.target.stat().st_mode),0o444)
        self.assertEqual(list(self.trust.iterdir()),[self.target])

    def test_leaf_and_ancestor_symlinks_wrong_mode_hardlink_and_oversize_rejected(self):
        for case in ('leaf','ancestor','mode','hardlink','oversize','owner'):
            with self.subTest(case=case):
                original=self.ca_path.read_bytes()
                if case=='leaf':
                    moved=self.tls/'other.pem';self.ca_path.rename(moved);self.ca_path.symlink_to(moved)
                elif case=='ancestor':
                    moved=self.root/'real-tls';self.tls.rename(moved);self.tls.symlink_to(moved,target_is_directory=True)
                elif case=='mode':self.ca_path.chmod(0o644)
                elif case=='hardlink':os.link(self.ca_path,self.tls/'second.pem')
                elif case=='oversize':self.ca_path.write_bytes(b'x'*16385)
                with mock.patch.object(M,'UID',os.getuid()+1 if case=='owner' else os.getuid()):
                    with self.assertRaises((M.C.Rejected,OSError)):M.read_fixture_provider_ca(self.selected)
                if case=='leaf':self.ca_path.unlink();moved.rename(self.ca_path)
                elif case=='ancestor':self.tls.unlink();moved.rename(self.tls)
                elif case=='mode':self.ca_path.chmod(0o600)
                elif case=='hardlink':(self.tls/'second.pem').unlink()
                elif case=='oversize':self.ca_path.write_bytes(original)

    def test_wrong_fixture_selection_and_directory_permissions_rejected(self):
        for selected in (self.root/'different.json',self.parent/'wrong'/M.F.FIXTURE_FILE,
                         self.base/'f-actual'/M.F.FIXTURE_FILE):
            with self.assertRaises(M.C.Rejected):M.read_fixture_provider_ca(selected)
        self.tls.chmod(0o755)
        with self.assertRaises(M.C.Rejected):M.read_fixture_provider_ca(self.selected)

    def test_single_ca_only_no_private_or_extra_payload(self):
        for raw in (b'',self.leaf,self.ca+self.ca,self.ca+b'private',b'prefix'+self.ca,
                    self.ca.replace(b'CERTIFICATE',b'PRIVATE KEY'),self.ca.replace(b'\n',b'\r\n'),
                    self.ca.replace(b'-----END',b'!-----END')):
            with self.subTest(raw_length=len(raw)),self.assertRaises(M.C.Rejected):M.validate_fixture_provider_ca(raw)

    def test_changed_public_file_and_parse_failure_do_not_publish(self):
        original=M.os.fstat;seen=0
        def changed(fd):
            nonlocal seen
            value=original(fd)
            if stat.S_ISREG(value.st_mode):
                seen+=1
                if seen==2:
                    altered=mock.Mock(wraps=value)
                    for key in ('st_dev','st_ino','st_mode','st_uid','st_gid','st_nlink','st_size','st_mtime_ns','st_ctime_ns'):
                        setattr(altered,key,getattr(value,key))
                    altered.st_mtime_ns+=1
                    return altered
            return value
        with mock.patch.object(M.os,'fstat',side_effect=changed),self.assertRaises(M.C.Rejected):
            M.read_fixture_provider_ca(self.selected)
        self.ca_path.write_bytes(self.ca+b'not-a-certificate')
        with self.root_adapter(),mock.patch.object(M.subprocess,'run') as verify,self.assertRaises(M.C.Rejected):
            M.install_fixture_provider_ca(self.selected,time.monotonic_ns()+10_000_000_000)
        verify.assert_not_called();self.assertFalse(self.target.exists())

    def test_bad_signature_never_publishes_trust(self):
        der=bytearray(ssl.PEM_cert_to_DER_cert(self.ca.decode()));der[-1]^=1
        self.ca_path.write_bytes(ssl.DER_cert_to_PEM_cert(bytes(der)).encode())
        with self.root_adapter(),self.assertRaises(M.C.Rejected):
            M.install_fixture_provider_ca(self.selected,time.monotonic_ns()+10_000_000_000)
        self.assertFalse(self.target.exists());self.assertEqual(list(self.trust.iterdir()),[])

    def test_verify_timeout_expiry_and_write_failure_leave_no_trust(self):
        for failure in ('timeout','expired','write'):
            with self.subTest(failure=failure),self.root_adapter(),contextlib.ExitStack() as stack:
                if failure=='timeout':stack.enter_context(mock.patch.object(M.subprocess,'run',side_effect=subprocess.TimeoutExpired('openssl',1)))
                if failure=='write':stack.enter_context(mock.patch.object(M.os,'fsync',side_effect=OSError('inert write failure')))
                deadline=time.monotonic_ns()+(-1 if failure=='expired' else 10_000_000_000)
                with self.assertRaises((M.C.Rejected,subprocess.TimeoutExpired,OSError)):
                    M.install_fixture_provider_ca(self.selected,deadline)
                self.assertFalse(self.target.exists());self.assertEqual(list(self.trust.iterdir()),[])

    def test_existing_target_or_wrong_fixed_link_is_never_overwritten(self):
        self.target.write_bytes(b'existing')
        with self.root_adapter(),self.assertRaises(M.C.Rejected):
            M.install_fixture_provider_ca(self.selected,time.monotonic_ns()+10_000_000_000)
        self.assertEqual(self.target.read_bytes(),b'existing')
        self.target.unlink();self.link.unlink();self.link.symlink_to(self.base/'other')
        with self.root_adapter(),self.assertRaises(M.C.Rejected):
            M.install_fixture_provider_ca(self.selected,time.monotonic_ns()+10_000_000_000)
        self.assertFalse(self.target.exists())

    def test_cleanup_uncertainty_preserves_original_failure(self):
        error=OSError('inert original publication failure')
        original=pathlib.Path.unlink
        def unlink(path,*args,**kwargs):
            if path==self.target:raise OSError('inert unlink failure')
            return original(path,*args,**kwargs)
        with self.root_adapter(),mock.patch.object(M.os,'fsync',side_effect=error), \
             mock.patch.object(pathlib.Path,'unlink',unlink):
            with self.assertRaises(OSError) as caught:
                M.install_fixture_provider_ca(self.selected,time.monotonic_ns()+10_000_000_000)
        self.assertIs(caught.exception,error)
        self.assertIs(error.fixture_trust_cleanup_unverified,True)
        self.assertTrue(self.target.exists()) # No false inner-cleanup claim.

    def test_public_fd_only_empty_environment_and_original_deadline(self):
        def verify(args,**kw):
            self.assertEqual(args[:5],['/usr/bin/openssl','verify','-x509_strict','-check_ss_sig','-CAfile'])
            self.assertEqual(args[5],args[-1]);self.assertEqual(args[6:8],['-no-CApath','-no-CAstore'])
            self.assertEqual(len(kw['pass_fds']),1)
            self.assertEqual(pathlib.Path(args[-1]).read_bytes(),self.ca)
            self.assertEqual(kw['env'],{});self.assertTrue(kw['close_fds'])
            self.assertEqual(kw['timeout'],2.0)
            for name in ('stdin','stdout','stderr'):self.assertEqual(kw[name],subprocess.DEVNULL)
            self.assertFalse(self.target.exists())
            return subprocess.CompletedProcess(args,0)
        with self.root_adapter(),mock.patch.object(M.subprocess,'run',side_effect=verify), \
             mock.patch.object(M.time,'monotonic_ns',return_value=5):
            M.install_fixture_provider_ca(self.selected,2_000_000_005)
        self.assertEqual(self.target.read_bytes(),self.ca)

    def test_source_bound_install_before_drop_and_native_environment_unchanged(self):
        source=(ROOT/'ci-financial-container.py').read_text();main=source[source.index('def main():'):]
        self.assertLess(main.index('install_fixture_provider_ca(parent.path,parent.deadline)'),main.index('os.setresuid(UID,UID,UID)'))
        self.assertLess(main.index('os.setresuid(UID,UID,UID)'),main.index('session=NativeSession'))
        self.assertIn("env={'XDG_RUNTIME_DIR':str(WAYLAND),'WAYLAND_DISPLAY':'wayland-financial'}",source)
        image=(ROOT/'ci-financial-image.py').read_text()
        self.assertIn("link.symlink_to('/etc/wholepact/fixture-provider-ca.pem')",image)
        self.assertIn("stat.S_IMODE(info.st_mode) == (0o755 if public == certs else 0o644)",image)
        self.assertIn("need(bundle.read_bytes() == original_bundle, 'input_digest')",image)
        body=source[source.index('def read_fixture_provider_ca'):source.index('def write_account')]
        self.assertNotIn('ca.key',body);self.assertNotIn('server.pk8',body)
        self.assertNotIn('SSL_CERT_FILE',body);self.assertNotIn('SSL_CERT_DIR',body)

if __name__=='__main__':unittest.main()
