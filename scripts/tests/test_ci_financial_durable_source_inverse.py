"""Strict historical restoration only; no native authority or runtime is exercised."""
import contextlib
import hashlib
import importlib.util
import io
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
AUDIT = ROOT / 'scripts/ci-financial-downstream-projection-audit.py'
spec = importlib.util.spec_from_file_location('p93_downstream_inverse', AUDIT)
A = importlib.util.module_from_spec(spec)
spec.loader.exec_module(A)
AUDIT_SHA = '0b13fd4e77525c870dbcc29565016675f402b9893b7e67da03b0073c13da48d1'
PRIOR_AUDIT_SHA = '6c937179892b412846835bf94763015030ff91fe778fbf7bdea8c127a61cf00e'
HOOK_PATH = 'crates/wholepact-signer/src/authority_bridge/financial_signing_v1.rs'
HOOK_SHA = '91aedd1bdf3e07e18a73a60745f75b729b4ccdeaa4658386d2be8933021722e6'
PRIOR_HOOK_SHA = '613c2ccde06afd6a8c6f30356dd5990f636059dec8970bd395277fc9437341e4'
HOOK_INVERSES = [('#[cfg(feature = "synthetic-born-joined-qualification")]\n#[path = "financial_signing_v1/durable_fail_stop_v2.rs"]\nmod durable_fail_stop_v2;\n#[cfg(feature = "synthetic-born-joined-qualification")]\npub(crate) use durable_fail_stop_v2::arm_durable_financial_started_fail_stop_v2;\n', ''), ('        )?;\n        #[cfg(feature = "synthetic-born-joined-qualification")]\n        durable_fail_stop_v2::after_started_commit(\n            &self.request.reservation.account_id,\n            &self.request.reservation.authorization_id,\n            self.source.original_deadline(),\n', '')]
FACILITY_PATH = 'crates/wholepact-signer/src/authority_bridge/financial_signing_v1/durable_fail_stop_v2.rs'
FACILITY_SHA = '7d1bb58e648a17cdd5836bd6f2f1d21ba06c9f8623b62ca3a955660bc30559d8'

def digest(text):
    return hashlib.sha256(text.encode()).hexdigest()

def restore_hook(text):
    assert digest(text) == HOOK_SHA
    for current, prior in HOOK_INVERSES:
        assert current and text.count(current) == 1
        text = text.replace(current, prior, 1)
    assert digest(text) == PRIOR_HOOK_SHA
    return text

class FinancialDurableSourceInverseTests(unittest.TestCase):
    def test_audit_extension_restores_entire_prior_script(self):
        text = AUDIT.read_bytes().decode('utf-8')
        self.assertEqual(digest(text), AUDIT_SHA)
        marker = '# Exact P93 sibling/result and qualification registrations back to whole P92.\n'
        self.assertEqual(text.count(marker), 1)
        start = text.index(marker)
        end = text.index('def main():\n', start)
        restored = text[:start] + text[end:]
        current = "raw={k:(r/k).read_bytes().decode('utf-8') for k in BASELINE_SHA256};restored=restore_durable_v2_sources(raw)"
        prior = 'raw={k:(r/k).read_text() for k in BASELINE_SHA256};restored=dict(raw)'
        self.assertEqual(restored.count(current), 1)
        restored = restored.replace(current, prior, 1)
        self.assertEqual(digest(restored), PRIOR_AUDIT_SHA)

    def test_current_sources_reach_complete_unchanged_historical_chain(self):
        raw = {path: (ROOT / path).read_bytes().decode('utf-8') for path in A.BASELINE_SHA256}
        restored = A.restore_durable_v2_sources(raw)
        self.assertEqual(len(A.P93_DURABLE_SOURCE_INVERSES), 7)
        for path, pin in A.P93_DURABLE_SOURCE_INVERSES.items():
            self.assertEqual(digest(restored[path]), pin['p92_sha256'])
        for path in set(raw) - set(A.P93_DURABLE_SOURCE_INVERSES):
            self.assertEqual(restored[path], raw[path])
        captured = io.StringIO()
        with patch.object(sys, 'argv', [str(AUDIT), '--source', str(ROOT)]), contextlib.redirect_stdout(captured):
            A.main()
        evidence = json.loads(captured.getvalue())
        self.assertEqual(evidence['baseline'], A.BASELINE)
        self.assertEqual(evidence['restored_files'], 13)
        self.assertEqual(evidence['pure_projections'], 6)
        self.assertFalse(evidence['executed_genuine_constructor'])

    def test_seven_current_gates_reject_stale_missing_duplicate_partial_and_unrelated_bytes(self):
        raw = {path: (ROOT / path).read_bytes().decode('utf-8') for path in A.BASELINE_SHA256}
        old = A.restore_durable_v2_sources(raw)
        for path, pin in A.P93_DURABLE_SOURCE_INVERSES.items():
            current, prior = pin['inverse'][0]
            cases = {
                'stale_p92': old[path],
                'missing': raw[path].replace(current, prior, 1),
                'duplicate': raw[path] + current,
                'partial': raw[path].replace(current, current[:-1], 1),
                'unrelated': raw[path] + '\n// unrelated source mutation\n',
                'changed_literal': raw[path].replace(current, current.replace('pub', 'pub_changed', 1) if 'pub' in current else current + 'changed', 1),
            }
            for name, text in cases.items():
                with self.subTest(path=path, mutation=name), self.assertRaises(AssertionError):
                    A.restore_durable_v2_sources({**raw, path: text})
        with self.assertRaises(AssertionError):
            A.restore_durable_v2_sources({**raw, 'unreviewed.rs': ''})

    def test_current_entry_rejects_crlf_byte_drift_before_restoration(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for path in A.BASELINE_SHA256:
                destination = root / path
                destination.parent.mkdir(parents=True, exist_ok=True)
                destination.write_bytes((ROOT / path).read_bytes())
            path = next(iter(A.P93_DURABLE_SOURCE_INVERSES))
            original = (root / path).read_bytes()
            self.assertNotIn(b'\r\n', original)
            (root / path).write_bytes(original.replace(b'\n', b'\r\n'))
            self.assertEqual((root / path).read_text(), original.decode('utf-8'))
            with patch.object(sys, 'argv', [str(AUDIT), '--source', str(root)]):
                with self.assertRaisesRegex(AssertionError, 'P93 source pin'):
                    A.main()

    def test_started_hook_is_exact_postcommit_prekey_remove_only_delta(self):
        text = (ROOT / HOOK_PATH).read_bytes().decode('utf-8')
        restored = restore_hook(text)
        self.assertNotIn('durable_fail_stop_v2', restored)
        self.assertLess(text.index('journal.begin_financial_key_use_v1('), text.index('durable_fail_stop_v2::after_started_commit('))
        self.assertLess(text.index('durable_fail_stop_v2::after_started_commit('), text.index('let publication = self.approved.publication_lease()?;'))
        self.assertLess(text.index('let publication = self.approved.publication_lease()?;'), text.index('let fence = FinancialKeyUseFenceV1 {'))
        facility = (ROOT / FACILITY_PATH).read_bytes().decode('utf-8')
        self.assertEqual(digest(facility), FACILITY_SHA)
        for exact in ['OnceLock<ArmedStartedStop>', 'armed.account != actual_account',
                      'armed.authorization != actual_authorization', 'armed.reached.swap(true, Ordering::AcqRel)',
                      'armed.outer_deadline.min(original_deadline)',
                      'DURABLE_STARTED_COMMITTED_BEFORE_KEY_USE_V2', 'std::thread::park_timeout',
                      'Err(BridgeError::Uncertain)']:
            self.assertIn(exact, facility)
        self.assertNotIn('std::env', facility)
        self.assertNotIn('unsafe', facility)
        for current, prior in HOOK_INVERSES:
            for mutated in [text.replace(current, prior, 1), text + current,
                            text.replace(current, current[:-1], 1), text + '// unrelated']:
                with self.assertRaises(AssertionError): restore_hook(mutated)

if __name__ == '__main__':
    unittest.main()
