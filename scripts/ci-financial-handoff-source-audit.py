#!/usr/bin/env python3
"""Source-preservation obligations for the coordinated purpose handoff.

This is a static regression, not a substitute for actual journal tests or flow.
Fixed hashes bind the exact P49c original kernels; no baseline checkout needed.
"""
import argparse
import hashlib
import json
from pathlib import Path


def function(source, signature):
    start = source.index(signature)
    opening = source.index('{', start)
    depth = 1
    cursor = opening + 1
    # The selected kernels contain no unmatched braces in literals/comments.
    # The fixed original hashes also make extraction drift fail closed.
    while depth:
        if cursor >= len(source):
            raise AssertionError('unterminated maintained source kernel')
        depth += (source[cursor] == '{') - (source[cursor] == '}')
        cursor += 1
    return source[start:cursor]


def digest(text):
    return hashlib.sha256(text.encode()).hexdigest()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--source', required=True, type=Path)
    args = parser.parse_args()
    root = args.source.resolve()
    signer = root / 'crates/wholepact-signer/src'
    obligations = [
        ('consent_journal/authority.rs',
         '    pub(super) fn require_spending_decision(',
         'bb0a79d15b79c6f7f3fa958e19e120a16a3458764473be7934b98a1f33ca065d', None),
        ('consent_journal/preconstruction_lease.rs',
         '    pub(crate) fn require_current_durable_disclosure_receipts_v1(',
         '595cba4ef891a20ac366ada447f9452ede0259a8e71e8763151092013da2e235', None),
        ('native_ui/durable_construction_v1.rs',
         'pub(crate) fn validate_original(',
         'b8845048e2bf7d064296249ff6a2a4eafd262ab90c5b0e02a1f24f6fc44f2170', None),
        ('consent_journal/prepared_delivery_v3/coordinated_admission_v1.rs',
         '    pub(in crate::consent_journal) fn with_coordinated_admission_effect_v1',
         '4adb347b78c767bbebffe263799156a272255c2fddf503ab4c0489b307b95e3d', 'require_admit(action)'),
        ('consent_journal/prepared_delivery_v3/coordinated_redisclosure_v1.rs',
         '    pub(in crate::consent_journal) fn with_coordinated_redisclosure_effect_v1',
         'd394a7c573e7ecb171c1411c4abf4b921eb24f8a04552436265803dd2e801975', 'require_export(action)'),
    ]
    evidence = []
    for relative, signature, expected, purpose in obligations:
        raw = (signer / relative).read_text()
        selected = function(raw, signature)
        restored = selected
        if purpose:
            assert selected.count(purpose) == 2, relative
            restored = restored.replace('CoordinatedPurposeRecordLease', 'PreconstructionRecordLease')
            restored = restored.replace(purpose, 'require_current_durable_disclosure_receipts_v1()')
            restored = restored.replace('// Purpose/provenance checks may wait: complete them BEFORE gate admission.',
                                        '// Nonce-map checks may wait: complete them BEFORE gate admission.')
        assert digest(restored) == expected, relative
        evidence.append({'path': relative, 'original_kernel_sha256': expected,
                         'current_file_sha256': digest(raw)})

    raw = (signer / 'native_ui/durable_construction_v1.rs').read_text()
    old = function(raw, 'pub(crate) fn validate_original(')
    new = function(raw, 'pub(crate) fn validate_coordinated_original(')
    assert new.replace('validate_coordinated_original(', 'validate_original(').replace(
        'CoordinatedPurposeRecordLease', 'PreconstructionRecordLease') == old

    authority = (signer / 'consent_journal/authority/coordinated_preconstruction_v1.rs').read_text()
    mint = function(authority, '    pub(crate) fn commit_manifest(')
    assert mint.index('receipt_progress.begin_manifest') < mint.index('self.approve_manifest')
    assert mint.index('let (record, pin) = result;') < mint.index('action.finish_review()')
    assert mint.index('action.finish_review()') < mint.index('self.require_current_receipts(')
    assert mint.index('self.require_current_receipts(') < mint.index('let accepted = CoordinatedAcceptedProvenanceV1 {')
    assert 'Ok((record, pin))' in mint

    enrollment = function(authority, '    pub(crate) fn commit_enrollment(')
    enrollment_old = enrollment.replace('&mut self,', '&self,', 1)
    enrollment_old = enrollment_old.replace(
        '        // Consume before any attempted effect. Failure/uncertainty cannot\n'
        '        // restore a receipt approval or permit a second publication attempt.\n'
        '        self.receipt_progress.begin_enrollment()?;\n', '')
    enrollment_old = enrollment_old.replace(
        '            self.receipt_progress = CoordinatedReceiptProgressV1::Enrollment(record.clone());\n', '')
    assert digest(enrollment_old) == '3dfdc796fd81fbd51562b4c032ee842f8ad9da5250ba506cc24302c8fb0128fe'

    # Reviewed handoff tail is the sole intentional replacement after an
    # original committed record+pin has already been retained. The prior core
    # is otherwise reconstructed byte-for-byte, including result ownership.
    assert digest(mint) == '39de729d43ab1cc30de6eeefbf6604f13a874ca79034f7b1b218067cf6922a5c'
    manifest_old = mint.replace('&mut self,', '&self,', 1).replace(
        'Result<(AcceptedManifestRecord, Result<(PreparedDeliveryJournalRevisionV3, CoordinatedAcceptedProvenanceV1)>)>',
        'Result<(AcceptedManifestRecord, Result<PreparedDeliveryJournalRevisionV3>)>')
    manifest_old = manifest_old.replace(
        '        let accepted_enrollment = self.receipt_progress.begin_manifest(&prepared.enrollment)?;\n', '')
    tail_start = manifest_old.index('            // This NEW nominal handoff')
    tail_end = manifest_old.index('            Ok((pin, accepted))', tail_start) + len('            Ok((pin, accepted))')
    manifest_old = manifest_old[:tail_start] + '            Ok(pin)' + manifest_old[tail_end:]
    assert digest(manifest_old) == '0c1a36f3e22c422e1948678600198f31867d1cd245adde9708fb84746e716f31'

    # Array-kernel tests cannot alone prove field-to-comparison wiring. Bind
    # the independently reviewed real21-identity/3-wall/4-Instant assembly.
    admission = (signer / 'consent_journal/durable_delivery_admission_intent_v3/coordinated_v1.rs').read_text()
    assembly = function(admission, '    pub(crate) fn purpose_binding(')
    assert digest(assembly) == '8854d2289249916a11ad5aed1e7b6c8b3cd4e6d2b1bf6c77547462024f16ca87'

    lease = (signer / 'consent_journal/preconstruction_lease/coordinated_v1.rs').read_text()
    assert 'base: PreconstructionRecordLease' in lease
    assert 'pub(crate) fn require_read(' in lease and 'pub(crate) fn require_prepare(' in lease
    assert 'pub(crate) fn require_admit(' in lease and 'pub(crate) fn require_export(' in lease
    assert 'pub(crate) fn require_admit_read(' in lease
    for forbidden in ['impl Clone for CoordinatedPurposeRecordLease',
                      'impl std::ops::Deref', 'fn into_generic', 'fn base(', 'fn permission(']:
        assert forbidden not in lease, forbidden
    acquisition = function(lease, '    pub(in crate::consent_journal) fn acquire_coordinated_preconstruction_records')
    assert acquisition.index('accepted.require_session_metadata(session)') < acquisition.index('self.connection.lock()')
    assert acquisition.index('accepted.require_held_session(&permission)') < acquisition.index('let fence =')

    print(json.dumps({'source_audit_passed': True, 'baseline':
        '835dace205c59ace14ffd750157a36e643b3f835', 'kernel_count': len(obligations),
        'runtime_execution': False, 'obligations': evidence}, sort_keys=True))


if __name__ == '__main__':
    main()
