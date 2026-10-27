"""Exact service-lifetime source custody; no compiler, sockets or native execution."""
import contextlib
import hashlib
import importlib.util
import io
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location('service_lifetime_source_tested', ROOT/'scripts/ci-financial-service-lifetime-trace.py')
G = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(G)
BASE = 'crates/wholepact-authority/src/native_witness_owner/window/'
HOST = 'crates/wholepact-native-host/src/host/manual_enrollment/command/roster_publication_v2/sequential_construction_v3_qualification/durable_proposal_v1/'
PARITY_FILES = tuple(BASE+name for name in G.P93_REEXPORTS) + (
    HOST+'coordinated_external_witness_v1.rs', HOST+'coordinated_full_fixture_v1.rs',
    'crates/wholepact-authority/src/transport.rs')


class ServiceLifetimeSourceTests(unittest.TestCase):
    def test_current_whole_source_parity_restores_both_exact_p92_files(self):
        G.source_parity(ROOT)
        self.assertEqual(set(G.P93_REEXPORTS), {'ephemeral_fixture_v1.rs', 'ephemeral_fixture_v1/durable_delivery_admission_v2.rs'})
        for name, (current, inserted, historical) in G.P93_REEXPORTS.items():
            raw = (ROOT/(BASE+name)).read_bytes()
            self.assertEqual(hashlib.sha256(raw).hexdigest(), current)
            text = raw.decode('utf-8')
            self.assertEqual(text.count(inserted), 1)
            restored = G.restore_p93_reexport(text, name)
            self.assertEqual(restored, text.replace(inserted, '', 1))
            self.assertEqual(G.digest(restored), historical)
        self.assertEqual(G.BASELINES, {
            'fixture': '9842053ac94015c10e9fb4c154da8a1c86b06fe209a51469e686541a6b4ecea8',
            'delivery': 'c5732e9b6d21a8ad2b5e643dde91fcef083fc6dc9e44a6eda560180ad50cc778',
            'external': 'f916850659a5ffa3d055020c031923e02d695791958f6fcec06f24b690152762',
            'full': '88daefaaaa935ad7ed8cce3e3891e6975fb84b98cce3081ae1e4a348bae8cc63',
            'transport': '2c58ec5ae515ce13786ec81661901c9ba1c72a5f9827d3c925e4fbc48e4f2716'})

    def test_generation_keeps_entire_historical_rust_and_never_invokes_compiler(self):
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp)/'out'
            with mock.patch.object(sys, 'argv', ['trace', '--source', str(ROOT), '--out', str(out)]), \
                 mock.patch.object(G.subprocess, 'run', side_effect=AssertionError('compiler/runtime forbidden')), \
                 contextlib.redirect_stdout(io.StringIO()) as stdout:
                G.main()
            self.assertEqual(json.loads(stdout.getvalue()), {'generated': True, 'executed': False, 'tests': 12})
            self.assertEqual({p.name for p in out.iterdir()}, {'service-lifetime-trace.rs', 'binding.json'})
            self.assertEqual(hashlib.sha256((out/'service-lifetime-trace.rs').read_bytes()).hexdigest(),
                             'be00e6477e6c1a7a55ea2b48cd0a6124638261bee5b182ddf3a384e24d298283')
            binding = json.loads((out/'binding.json').read_bytes())
            self.assertEqual(binding['test_count'], 12)
            self.assertEqual(binding['old_loop_sha256'], G.OLD_LOOP_HASH)
            self.assertEqual(binding['files'], {name: hashlib.sha256((ROOT/name).read_bytes()).hexdigest() for name in (
                BASE+'ephemeral_fixture_v1.rs', BASE+'ephemeral_fixture_v1/coordinated_history_lifetime_v1.rs')})

    def test_entire_parity_rejects_missing_duplicate_partial_stale_and_unrelated_bytes(self):
        originals = {name: (ROOT/name).read_bytes() for name in PARITY_FILES}
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            for name, raw in originals.items():
                p = root/name; p.parent.mkdir(parents=True, exist_ok=True); p.write_bytes(raw)
            G.source_parity(root)
            for name, (_, inserted, _) in G.P93_REEXPORTS.items():
                relative = BASE+name; raw = originals[relative]; line = inserted.encode()
                mutants = {
                    'missing_or_stale_p92': raw.replace(line, b'', 1),
                    'duplicate': raw.replace(line, line+line, 1),
                    'partial': raw.replace(line, line[:-2]+b'\n', 1),
                    'renamed': raw.replace(line, line.replace(b'WitnessV2', b'WitnessV3'), 1),
                    'unrelated': raw+b'// unrelated source drift\n',
                    'crlf': raw.replace(b'\n', b'\r\n'),
                    'truncated': raw[:-1],
                }
                for label, bad in mutants.items():
                    with self.subTest(file=name, mutation=label):
                        self.assertNotEqual(raw, bad)
                        (root/relative).write_bytes(bad)
                        with self.assertRaises(AssertionError):
                            G.source_parity(root)
                (root/relative).write_bytes(raw)
            G.source_parity(root)


if __name__ == '__main__':
    unittest.main()
