"""Pure lock tests; no downloads, OCR execution, installation or container."""
import copy
import importlib.util
import pathlib
import sys
import unittest
ROOT=pathlib.Path(__file__).resolve().parents[1]
spec=importlib.util.spec_from_file_location('financial_ocr_image_tested',ROOT/'ci-financial-ocr-image.py')
M=importlib.util.module_from_spec(spec);sys.modules[spec.name]=M;spec.loader.exec_module(M)
RAW=(ROOT/'ci-financial-ocr-packages.json').read_bytes()
BASE=(ROOT/'ci-ui-packages.json').read_bytes()

class OcrLockTests(unittest.TestCase):
    def test_exact_lock_and_closure(self):
        manifest,base=M.validate_manifest(RAW,BASE)
        self.assertEqual(len(manifest['ocr_closure']),93)
        self.assertEqual(len(M.download_plan(manifest)),16)
        self.assertEqual(sum(r['size'] for r in M.download_plan(manifest)),9069168)
    def test_mutated_lock_never_accepted(self):
        with self.assertRaises(M.Rejected):M.validate_manifest(RAW+b' ',BASE)
    def test_changed_base_lock_never_accepted(self):
        with self.assertRaises(M.Rejected):M.validate_manifest(RAW,BASE+b' ')
    def test_no_base_upgrade(self):
        manifest,base=M.validate_manifest(RAW,BASE)
        expected=M.expected_runtime_packages(manifest,base)
        for row in base['base_packages']:
            self.assertEqual(expected[row['name']],[row['version'],row['architecture']])
    def test_only_reviewed_official_downloads(self):
        manifest,_=M.validate_manifest(RAW,BASE)
        for row in M.download_plan(manifest):
            self.assertTrue(row['url'].startswith('https://deb.debian.org/debian/pool/main/'))
            self.assertEqual(len(row['sha256']),64);self.assertGreater(row['size'],0)
    def test_mutated_inmemory_manifest_not_accepted(self):
        manifest,_=M.validate_manifest(RAW,BASE);manifest['executable']['sha256']='0'*64
        with self.assertRaises(M.Rejected):M.download_plan(manifest)
    def test_unpinned_executable_rejected(self):
        manifest,_=M.validate_manifest(RAW,BASE)
        with self.assertRaises(M.Rejected):M.validate_executable(manifest,b'not tesseract')
    def test_unpinned_index_rejected_before_parse(self):
        manifest,_=M.validate_manifest(RAW,BASE)
        with self.assertRaises(M.Rejected):M.audit_authenticated_index(manifest,b'not pinned')
    def test_installed_closure_is_exact(self):
        manifest,base=M.validate_manifest(RAW,BASE)
        expected=M.expected_runtime_packages(manifest,base)
        lines=['\t'.join([name,*version,'installed']) for name,version in sorted(expected.items())]
        raw='\n'.join(lines)+'\n';M.validate_installed(manifest,base,raw)
        with self.assertRaises(M.Rejected):M.validate_installed(manifest,base,'\n'.join(lines[:-1]))
        with self.assertRaises(M.Rejected):M.validate_installed(manifest,base,raw+'xwayland\t1\tamd64\tinstalled\n')

if __name__=='__main__':unittest.main()
