#!/usr/bin/env python3
"""Source-only regression checks, not payment/native-approval qualification."""
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[2]
SIGN = ROOT / 'crates/wholepact-signer/src/authority_bridge/financial_signing_v1.rs'
SESSION = ROOT / 'crates/wholepact-signer/src/consent_journal/financial_session_v1.rs'
BRIDGE = ROOT / 'crates/wholepact-signer/src/consent_journal/financial_bridge_storage_v1.rs'


def body(text, start, end):
    return text.split(start, 1)[1].split(end, 1)[0]


class MaintainedSignKernelSource(unittest.TestCase):
    def test_native_entry_keeps_started_before_keyuse_and_result_after(self):
        code = body(SIGN.read_text(), '    fn sign_held(', '\nstruct FinancialWalletPermission')
        ordered = ['verify_exact_signing_material_kernel(',
                   'journal.begin_financial_key_use_v1(',
                   'self.approved.publication_lease()',
                   'sign_exact_result_kernel(',
                   'drop(publication)',
                   'journal.retain_financial_result_v1(']
        offsets = [code.index(value) for value in ordered]
        self.assertEqual(offsets, sorted(offsets))

    def test_private_crypto_kernel_keeps_exact_normalization_and_indices(self):
        code = body(SIGN.read_text(), 'fn sign_exact_result_kernel(',
                    '\n/// Exact fixed-input/PCZT verification')
        self.assertIn('for &action_index in actual', code)
        self.assertIn('.sign_ironwood(UnwrapErr(SysRng), action_index, &ask)', code)
        self.assertIn('a.clear_spend_auth_sig()', code)
        self.assertIn('!= *bytes', code)
        self.assertIn('verify_review(&signed_bytes, &inputs.policy)', code)
        self.assertNotIn('.reserve_', code)
        self.assertNotIn('tx.commit', code)
        self.assertNotIn('.await', code)

    def test_private_verifier_keeps_fixed_inputs_wallet_and_existing_sig_rejection(self):
        code = SIGN.read_text().split('fn verify_exact_signing_material_kernel(', 1)[1]
        for exact in ['verify_action_mappings', 'wallet.transaction_expiry_height()',
                      'evidence.inputs().len()', 'verify_proved_candidate',
                      'a.spend().spend_auth_sig().is_some()',
                      'actual.iter().map(|input| input.action_index).collect()']:
            self.assertIn(exact, code)

    def test_inert_preparation_has_no_approval_or_key_use(self):
        code = body(SESSION.read_text(), '    fn prepare_financial_spend_data_v1(',
                    '\nimpl PreparedFinancialSpendV1')
        self.assertIn('crate::manifest::reconcile(', code)
        self.assertIn('fixed\n            .verify_action_mappings(', code)
        self.assertNotIn('FinancialSignActionV1', code)
        self.assertNotIn('derive_financial_spending_key_v1', code)
        self.assertNotIn('sign_ironwood', code)

    def test_coordinated_sign_reuses_actual_observed_fvk_before_started(self):
        source = ROOT / 'crates/wholepact-signer/src'
        wallet = (source / 'native_ui/wallet_workspace/coordinated_financial_sign_v1.rs').read_text()
        coordinated = (source / 'authority_bridge/coordinated_financial_signing_v1.rs').read_text()
        preparation = SESSION.read_text()
        self.assertIn('let evidence=ticket.evidence();', wallet)
        self.assertIn('digest!=self.report.wallet_observation_digest', wallet)
        self.assertIn('let observed_fvk=evidence.fvk().clone();', wallet)
        self.assertIn('self.inputs,&observed_fvk,history,active', wallet)
        self.assertIn('let fvk=self.approved.authenticated_fvk().clone();', coordinated)
        self.assertNotIn('let fvk=account.fvk()', coordinated)
        self.assertIn('Self::Native(_) => account.fvk()', preparation)
        self.assertIn('Self::Coordinated(_, fvk) => Ok((**fvk).clone())', preparation)
        self.assertIn('enrollment.account_fvk_digest()', preparation)
        self.assertIn('crate::manifest::reconcile(', preparation)

    def test_started_row_is_never_reused(self):
        code = body(BRIDGE.read_text(), '\nfn begin_key_use_rows(',
                    '\n// Exact rows only;')
        self.assertIn('if started {return Err(BridgeError::Uncertain);}', code)
        self.assertNotIn('INSERT OR REPLACE', code)


if __name__ == '__main__':
    unittest.main()
