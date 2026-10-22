#!/usr/bin/env python3
"""Pure manifest and fabricated-byte file tests; never execute binary inputs."""
import copy
import hashlib
import importlib.util
import pathlib
import tempfile
import unittest

spec = importlib.util.spec_from_file_location('financial_artifacts', pathlib.Path(__file__).parents[1] / 'ci-financial-artifacts.py')
A = importlib.util.module_from_spec(spec); spec.loader.exec_module(A)
IDENTITY = dict(repository='stanleykosi/pactloom', source='a'*40, source_tree='b'*40, run_id=123, attempt=1)
CLOSURE = {'Cargo.lock': 'a'*64, 'crates/example/src/lib.rs': 'b'*64}

class BundleTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(); self.addCleanup(self.temp.cleanup)
        self.root = pathlib.Path(self.temp.name)
        self.inputs = self.root / 'inputs'; self.inputs.mkdir()
        for name in A.NAMES:
            (self.inputs / name).write_bytes(b'\x7fELFfabricated, never executable ' + name.encode())
        self.output = self.root / 'bundle.tar'

    def export(self):
        return A.export_bundle(self.inputs, self.output, IDENTITY, CLOSURE)

    def test_exact_roundtrip_and_modes(self):
        value = self.export()
        self.assertEqual(A.verify_bundle(self.output, IDENTITY, CLOSURE), value)
        self.assertEqual(self.output.stat().st_mode & 0o777, 0o444)
        self.assertEqual(set(value['files']), set(A.NAMES))

    def test_output_never_overwrites(self):
        self.export()
        before = self.output.read_bytes()
        with self.assertRaises(FileExistsError): self.export()
        self.assertEqual(self.output.read_bytes(), before)

    def test_private_extra_file_refused(self):
        (self.inputs / 'private.key').write_bytes(b'fabricated')
        with self.assertRaises(A.Rejected): self.export()
        self.assertFalse(self.output.exists())

    def test_symlink_and_hardlink_refused(self):
        path = self.inputs / A.NAMES[0]
        path.unlink(); path.symlink_to(self.inputs / A.NAMES[1])
        with self.assertRaises(A.Rejected): self.export()
        path.unlink(); path.hardlink_to(self.inputs / A.NAMES[1])
        with self.assertRaises(A.Rejected): self.export()

    def test_provenance_and_source_closure_are_exact(self):
        self.export()
        for key, value in [('repository','other/repo'), ('source','c'*40),
                           ('source_tree','c'*40), ('run_id',124), ('attempt',2)]:
            with self.assertRaises(A.Rejected):
                A.verify_bundle(self.output, {**IDENTITY,key:value}, CLOSURE)
        for closure in ({'Cargo.lock':'a'*64}, {**CLOSURE,'Cargo.toml':'c'*64},
                        {**CLOSURE,'Cargo.lock':'c'*64}):
            with self.assertRaises(A.Rejected): A.verify_bundle(self.output, IDENTITY, closure)

    def test_modified_binary_and_hidden_tail_refused(self):
        self.export(); original = self.output.read_bytes()
        modified = original.replace(b'fabricated, never', b'fabricated, wrong', 1)
        self.output.chmod(0o600); self.output.write_bytes(modified)
        with self.assertRaises(A.Rejected): A.verify_bundle(self.output, IDENTITY, CLOSURE)
        self.output.write_bytes(original + b'private-tail')
        with self.assertRaises(A.Rejected): A.verify_bundle(self.output, IDENTITY, CLOSURE)

    def test_recipe_not_merely_asserted(self):
        value = self.export(); value = copy.deepcopy(value)
        value['recipe']['observed_rustflags'] = ''
        with self.assertRaises(A.Rejected): A.validate_manifest(value, IDENTITY, CLOSURE)

    def test_recipe_booleans_are_not_numbers(self):
        value = self.export()
        for key in ('locked', 'static_crypto', 'default_features'):
            changed = copy.deepcopy(value)
            changed['recipe'][key] = int(changed['recipe'][key])
            with self.assertRaises(A.Rejected): A.validate_manifest(changed, IDENTITY, CLOSURE)

    def test_manifest_rejects_extra_fields_and_bad_paths(self):
        value = self.export()
        with self.assertRaises(A.Rejected): A.validate_manifest({**value, 'secret':'x'}, IDENTITY, CLOSURE)
        for path in ('../secret','/private','a//b','a/./b'):
            with self.assertRaises(A.Rejected): A.closure({path:'a'*64})
        with self.assertRaises(A.Rejected): A.identity({**IDENTITY,'run_id':True})

if __name__ == '__main__': unittest.main()
