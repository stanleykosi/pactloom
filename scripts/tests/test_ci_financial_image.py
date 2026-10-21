"""Pure rendering/closure tests; no downloads, package install or Docker."""
import importlib.util
import pathlib
import sys
import unittest
ROOT=pathlib.Path(__file__).resolve().parents[1]
spec=importlib.util.spec_from_file_location('financial_image_tested',ROOT/'ci-financial-image.py')
M=importlib.util.module_from_spec(spec);sys.modules[spec.name]=M;spec.loader.exec_module(M)
class FinancialImageTests(unittest.TestCase):
    def test_exact_pinned_base_and_stages(self):
        text=M.dockerfile()
        self.assertEqual(text.count('FROM --platform=linux/amd64 '+M.BASE_IMAGE),2)
        self.assertIn(' AS foundation',text);self.assertIn('FROM foundation AS runtime',text)
        self.assertNotIn('apt-get',text);self.assertNotIn('ADD ',text)
    def test_pristine_owner_and_readonly_modes(self):
        text=M.dockerfile()
        self.assertIn('COPY --chown=10001:10001 --chmod=0555 artifacts/pristine-setup',text)
        for name in ('coordinator-production','coordinator-observed'):
            self.assertIn('COPY --chown=0:0 --chmod=0555 artifacts/'+name,text)
    def test_exact_entrypoint_empty_cmd(self):
        text=M.dockerfile()
        self.assertIn('ENTRYPOINT ["/usr/local/bin/python3","-I","-B","/opt/ci-financial/ci-financial-container.py"]',text)
        self.assertIn('CMD []',text)
    def test_generated_installer_parses_and_excludes_old_profile(self):
        text=M.installer();compile(text,'generated-financial-installer','exec')
        self.assertNotIn('/opt/ci-ui',text);self.assertNotIn('ci-ui-weston-module',text)
        self.assertIn("symlink_to('/run/ci-account/passwd')",text)
        self.assertIn("(ROOT / 'base-passwd').chmod(0o444)",text)
    def test_exact_runtime_inputs(self):
        names=M.runtime_files()
        self.assertEqual(len(names),10);self.assertNotIn(M.MODULE_BINARY,names)
        self.assertIn('ci-financial-external-operator.py',names)
    def test_metadata_has_exact_addon_and_no_base_change(self):
        ocr,base=M.O.validate_manifest((ROOT/'ci-financial-ocr-packages.json').read_bytes(),(ROOT/'ci-ui-packages.json').read_bytes())
        names=(*M.runtime_files(),M.MODULE_SOURCE,*M.ARTIFACT_FILES)
        pins={n:{'size':1,'sha256':'0'*64} for n in names}
        meta=M.metadata(base,ocr,pins,'1'*40)
        self.assertEqual(len(meta['runtime']),318)
        self.assertEqual(meta['base'],M.B.expected_packages(base,'base'))
        package_names={r['name'] for mode in meta['packages'].values() for r in mode}
        self.assertEqual(len(package_names),274)
        self.assertEqual(meta['profile'],'coordinated-financial-external-pre-v3-witness-v1')
    def test_missing_input_or_fake_source_rejected(self):
        ocr,base=M.O.validate_manifest((ROOT/'ci-financial-ocr-packages.json').read_bytes(),(ROOT/'ci-ui-packages.json').read_bytes())
        with self.assertRaises(Exception):M.metadata(base,ocr,{},'1'*40)
        with self.assertRaises(Exception):M.metadata(base,ocr,{},'not-a-commit')
    def test_runtime_verifies_exact_ocr_bytes_without_execute(self):
        text=M.installer()
        self.assertIn("verify(pathlib.Path(ocr['path']), {'size':ocr['bytes'],'sha256':ocr['sha256']})",text)
        self.assertNotIn("checked(['tesseract'",text)
if __name__=='__main__':unittest.main()
