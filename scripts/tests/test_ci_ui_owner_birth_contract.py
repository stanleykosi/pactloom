"""Source-contract regression only; no Rust/native execution or fixture creation."""
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[2]
OWNER = next((ROOT / 'crates/wholepact-native-host/src').rglob('pristine_owner_client_v1.rs')).read_text()
AUTH = ROOT / 'crates/wholepact-authority/src'
PRODUCER = (AUTH / 'native_witness_owner/window/ephemeral_fixture_v1/durable_delivery_admission_v2.rs').read_text()
AUDIT = (AUTH / 'native_witness_owner/window/ephemeral_fixture_v1/pristine_audit_v1.rs').read_text()

class OriginalBirthContract(unittest.TestCase):
    def test_producer_preserves_complete_envelope_not_digest(self):
        self.assertIn('original_signed_birth: String::from_utf8(envelope)', PRODUCER)
        self.assertNotIn('a.original_signed_birth.len() == 64', OWNER)

    def test_consumer_bounds_and_typed_parses_original(self):
        helper = OWNER.split('fn original_birth(', 1)[1].split('fn require_original_births(', 1)[0]
        self.assertIn('raw.is_empty()', helper)
        self.assertIn('raw.len() > wholepact_authority::MAX_FRAME_BYTES', helper)
        self.assertIn('PendingBirthOwnerSignature', helper)
        self.assertIn('serde_json::from_str(raw)', helper)

    def test_validates_signature_against_independent_owner_before_request_return(self):
        helper = OWNER.split('fn require_original_births(', 1)[1].split('fn validate_shape(', 1)[0]
        self.assertIn('hex::decode(&f.form.owner_certificate_der_hex)', helper)
        self.assertIn('verify_pending_birth_owner_signature(', helper)
        self.assertIn('&signed, &owner_pin', helper)
        for field in ['account_id', 'network_profile_id', 'witness_id', 'endpoint', 'server_name', 'pinned_server_certificate_digest']:
            self.assertIn('disclosure.' + field + ' !=', helper)
        self.assertIn('require_original_births(f)?;\n    Ok(request)', OWNER)

    def test_actual_postdrain_audit_remains_not_replaced_by_json_claim(self):
        for fragment in ['verify_pending_birth_owner_signature(', 'verified.request() != &birth.request',
                         'verified.evidence_digest() != birth.owner_approval_evidence_digest',
                         'verify_exact_append(&journal, account, &request)?']:
            self.assertIn(fragment, AUDIT)

    def test_genuine_fixture_exercises_positive_and_tampered_envelopes_before_handoff(self):
        producer = next((ROOT / 'crates/wholepact-native-host/src').rglob('pristine_coordinator_v1.rs')).read_text()
        self.assertIn('check_actual_birth_envelope_contract(&encoded)?', producer)
        self.assertLess(producer.index('check_actual_birth_envelope_contract(&encoded)?'), producer.index('let kept = root.keep()'))
        regression = OWNER.split('fn check_actual_birth_envelope_contract(', 1)[1].split('fn one_original_attempt(', 1)[0]
        self.assertIn('validate_shape(&original)?', regression)
        self.assertIn('byte ^ 1', regression)
        self.assertIn('"restored_approval"', regression)
        self.assertIn('if validate_shape(&changed).is_ok() { return Err(refused()); }', regression)

if __name__ == '__main__':
    unittest.main()
