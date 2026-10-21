#!/usr/bin/env python3
"""Pure fabricated bundles/API responses/mocked controller; no network/native work."""
import hashlib
import importlib.util
import io
import json
import pathlib
import tempfile
import unittest
import zipfile
from unittest import mock

spec=importlib.util.spec_from_file_location('ui_reuse_runner_test',pathlib.Path(__file__).parents[1]/'ci-ui-reuse-runner.py')
U=importlib.util.module_from_spec(spec);spec.loader.exec_module(U)
IDENTITY=dict(repository=U.A.REPOSITORY,source='a'*40,source_tree='b'*40,run_id=10,attempt=1)
CLOSURE={p:'a'*64 for p in ('Cargo.lock','Cargo.toml','scripts/ci-ui-supervisor.py')}

class Caller(unittest.TestCase):
    def test_null_pin_uses_original_path_and_removes_token(self):
        with tempfile.TemporaryDirectory() as directory:
            pin=pathlib.Path(directory)/'pin.json';pin.write_text('null\n')
            with mock.patch.object(U,'PIN',pin),mock.patch.object(U.S,'context',return_value=('a'*40,'t')), \
                 mock.patch.object(U.S,'exact_source'),mock.patch.object(U.S,'main',return_value=17) as main, \
                 mock.patch.object(U,'api') as api,mock.patch.dict(U.os.environ,{'UI_ARTIFACT_READ_TOKEN':'synthetic-token'}):
                self.assertEqual(U.run(),17)
                self.assertNotIn('UI_ARTIFACT_READ_TOKEN',U.os.environ)
                main.assert_called_once();api.assert_not_called()

    def test_storage_allowlist_and_no_redirect(self):
        self.assertEqual(U.storage_url('https://example.blob.core.windows.net/x?sig=fake'),
                         'https://example.blob.core.windows.net/x?sig=fake')
        for url in ('http://x.blob.core.windows.net/x','https://x.blob.core.windows.net.evil/x',
                    'https://user:secret@x.blob.core.windows.net/x','https://evil.test/x',
                    'https://x.blob.core.windows.net:444/x'):
            with self.assertRaises(U.Rejected):U.storage_url(url)
        self.assertIsNone(U.NoRedirect().redirect_request(None,None,302,'',{},'https://evil.test'))

    def test_anonymous_storage_request_never_contains_api_token(self):
        content=b'fabricated zip';response=mock.MagicMock()
        response.__enter__.return_value=response;response.status=200
        response.geturl.return_value='https://x.blob.core.windows.net/a'
        response.read1.side_effect=[content,b'']
        opener=mock.Mock();opener.open.return_value=response
        with tempfile.TemporaryDirectory() as directory, mock.patch.object(U.urllib.request,'build_opener',return_value=opener):
            U.download_archive(response.geturl.return_value,pathlib.Path(directory)/'x',hashlib.sha256(content).hexdigest())
            request=opener.open.call_args.args[0]
            self.assertEqual(request.headers,{})

    def test_late_api_eof_is_rejected(self):
        response=mock.MagicMock();response.__enter__.return_value=response
        response.status=200;response.geturl.return_value=U.API+'actions/jobs/1'
        response.read1.return_value=b''
        opener=mock.Mock();opener.open.return_value=response
        with mock.patch.object(U.urllib.request,'build_opener',return_value=opener), \
             mock.patch.object(U.time,'monotonic',side_effect=[0,0,61]):
            with self.assertRaises(U.Rejected) as found:U.api('actions/jobs/1','')
            self.assertEqual(str(found.exception),'api_deadline')

    def test_late_download_eof_is_rejected(self):
        response=mock.MagicMock();response.__enter__.return_value=response
        response.status=200;response.geturl.return_value='https://x.blob.core.windows.net/a'
        response.read1.return_value=b''
        opener=mock.Mock();opener.open.return_value=response
        with tempfile.TemporaryDirectory() as directory, \
             mock.patch.object(U.urllib.request,'build_opener',return_value=opener), \
             mock.patch.object(U.time,'monotonic',side_effect=[0,0,301]):
            with self.assertRaises(U.Rejected) as found:
                U.download_archive(response.geturl.return_value,pathlib.Path(directory)/'x','a'*64)
            self.assertEqual(str(found.exception),'download_deadline')

    def test_original_refusal_survives_cleanup_error(self):
        pin=dict(version=1,repository=U.R.REPOSITORY,source='a'*40,source_tree='b'*40,
                 run_id=10,attempt=1,job_id=20,artifact_id=30,archive_sha256='c'*64,bundle_sha256='d'*64)
        with tempfile.TemporaryDirectory() as directory:
            path=pathlib.Path(directory)/'pin.json';path.write_text(json.dumps(pin))
            with mock.patch.object(U,'PIN',path),mock.patch.object(U.S,'context',return_value=('e'*40,'t')), \
                 mock.patch.object(U.S,'exact_source'),mock.patch.object(U,'api',side_effect=U.Rejected('api_response')), \
                 mock.patch.object(U.shutil,'rmtree',side_effect=OSError('PRIVATE')), \
                 mock.patch.dict(U.os.environ,{'RUNNER_TEMP':directory}),mock.patch('builtins.print') as printed:
                with self.assertRaises(U.Rejected) as found:U.run()
                self.assertEqual(str(found.exception),'api_response')
                printed.assert_called_once_with('CI_UI_REUSE_CLEANUP {"removed":false}',flush=True)

    def test_exact_single_bundle_and_restored_bytes(self):
        with tempfile.TemporaryDirectory() as directory:
            root=pathlib.Path(directory);inputs=root/'inputs';inputs.mkdir()
            for name in U.A.NAMES:(inputs/name).write_bytes(b'\x7fELFfake '+name.encode())
            bundle=root/'build.tar';U.A.export_bundle(inputs,bundle,IDENTITY,CLOSURE)
            zipped=root/'archive.zip'
            with zipfile.ZipFile(zipped,'w',compression=zipfile.ZIP_DEFLATED) as out:out.write(bundle,'build.tar')
            recovered=root/'received.tar'
            U.unpack_single_bundle(zipped,recovered,hashlib.sha256(bundle.read_bytes()).hexdigest())
            files,changes=U.manifest_and_restore(recovered,IDENTITY,CLOSURE,root/'restored')
            self.assertEqual(changes,[])
            for name in U.A.NAMES:self.assertEqual((root/'restored'/name).read_bytes(),(inputs/name).read_bytes())
            self.assertEqual(set(files),set(U.A.NAMES))

    def test_zip_extra_paths_and_bad_digest_are_refused(self):
        for name in ('../build.tar','other.tar'):
            with tempfile.TemporaryDirectory() as directory:
                root=pathlib.Path(directory)
                with zipfile.ZipFile(root/'a.zip','w') as out:out.writestr(name,b'fake')
                with self.assertRaises(U.Rejected):U.unpack_single_bundle(root/'a.zip',root/'out','a'*64)
        with tempfile.TemporaryDirectory() as directory:
            root=pathlib.Path(directory)
            with zipfile.ZipFile(root/'a.zip','w') as out:
                out.writestr('build.tar',b'fake');out.writestr('extra',b'private')
            with self.assertRaises(U.Rejected):U.unpack_single_bundle(root/'a.zip',root/'out','a'*64)

    def test_compile_inputs_changed_refuses_before_restore(self):
        with tempfile.TemporaryDirectory() as directory:
            root=pathlib.Path(directory);inputs=root/'inputs';inputs.mkdir()
            for name in U.A.NAMES:(inputs/name).write_bytes(b'\x7fELFfake')
            bundle=root/'build.tar';U.A.export_bundle(inputs,bundle,IDENTITY,CLOSURE)
            with self.assertRaises(U.R.Rejected):U.manifest_and_restore(bundle,IDENTITY,
                {**CLOSURE,'Cargo.lock':'b'*64},root/'restored')
            self.assertFalse((root/'restored').exists())

if __name__=='__main__':unittest.main()
