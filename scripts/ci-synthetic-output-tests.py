#!/usr/bin/env python3
"""Pure public parser/selection tests. No child, socket, key or wallet is created."""
import importlib.util
import contextlib
import io
import json
import pathlib
import re
import unittest
from unittest import mock

ROOT=pathlib.Path(__file__).resolve().parent.parent
spec=importlib.util.spec_from_file_location('ci_output', ROOT/'scripts/ci-synthetic-output.py')
output=importlib.util.module_from_spec(spec)
spec.loader.exec_module(output)
build_spec=importlib.util.spec_from_file_location('ci_build_errors', ROOT/'scripts/ci-synthetic-build-errors.py')
build_errors=importlib.util.module_from_spec(build_spec)
build_spec.loader.exec_module(build_errors)

class PublicOutputTests(unittest.TestCase):
    def record(self):
        row={key:False for key in output.FALSE_FIELDS}
        row.update({key:1 for key in output.INT_FIELDS})
        row.update(evidence_kind='synthetic_full_payment_v1',transaction_id='a'*64,
                   transaction_bytes_sha256='b'*64,network='testnet',
                   submission_outcome='synthetic_acknowledged',consensus_branch_id=0x77190ad9,
                   expiry_height=100,recipient_decrypted_zatoshis=100000,
                   fabricated_tip_height=3,required_confirmations=3)
        return row

    def test_core_policy_reports_only_unmodified_process_policy(self):
        line='[JOINED_CORE_POLICY inherited_limit=Zero collector=Pipe process_dumpability=Unchanged crash_copy_absence_verified=false]'
        self.assertIsNotNone(output.CORE.fullmatch(line))
        self.assertIsNone(output.CORE.fullmatch(line.replace('Unchanged','Disabled')))
        self.assertIsNone(output.CORE.fullmatch(line.replace('verified=false','verified=true')))

    def test_exact_listing_requires_one_named_test_and_summary(self):
        name=output.TESTS['initial'][0]
        known=name+': test\n\n1 test, 0 benchmarks\n'
        self.assertTrue(output.exact_listing(known,name))
        self.assertTrue(output.exact_listing(known.rstrip('\n'),name))
        for invalid in ['',name+': test\n','0 tests, 0 benchmarks\n',known+'private',
                        known.replace('1 test','2 tests'),known.replace(name,'another'),
                        name+': test\nanother: test\n\n2 tests, 0 benchmarks\n']:
            self.assertFalse(output.exact_listing(invalid,name))

    def test_public_outcome_exact_positive(self):
        row=self.record()
        self.assertEqual(output.public_outcome(json.dumps(row)),row)
        self.assertEqual(len(row),20)

    def test_public_outcome_unknown_duplicate_missing_or_stronger_claims_refused(self):
        row=self.record()
        cases=[dict(row,private='forbidden'),{k:v for k,v in row.items() if k!='schema'}]
        cases.extend(dict(row,**{k:True}) for k in output.FALSE_FIELDS)
        for value in cases:
            with self.assertRaises(ValueError): output.public_outcome(json.dumps(value))
        with self.assertRaises(ValueError):
            output.public_outcome(json.dumps(row)[:-1]+',"schema":1}')

    def test_public_outcome_numeric_digest_and_size_bounds(self):
        for field,value in [('schema',True),('expiry_height',2**32),('schema',2**16),
                            ('recipient_decrypted_zatoshis',2**64),('required_confirmations',33),
                            ('fabricated_inclusion_height',4),('transaction_id','C'*64),
                            ('submission_attempt',2),('network','mainnet')]:
            with self.assertRaises(ValueError): output.public_outcome(json.dumps(dict(self.record(),**{field:value})))
        with self.assertRaises(ValueError): output.public_outcome(' '*4097)

    def failure(self,summary='SingleIpcBind:IoKind=PermissionDenied:errno=1',reason='ChildExit'):
        return '[JOINED_FAILURE exit=Some(101) signal=None core_dumped=false inputs=1/2 reason='+reason+' static_boundaries='+summary+']'

    def test_harness_failure_reasons_match_exact_rust_enum(self):
        source=(ROOT/'crates/wholepact-native-host/src/host/manual_enrollment/command/roster_publication_v2/sequential_construction_v3_qualification.rs').read_text()
        body=re.search(r'enum HarnessFailureReason \{([^}]+)\}',source).group(1)
        variants=set(re.findall(r'^    ([A-Za-z0-9]+),$',body,re.M))
        self.assertEqual(variants,output.HARNESS_FAILURE_REASONS)
        self.assertEqual(len(variants),17)
        self.assertIn('inputs={}/{} reason={:?} static_boundaries={}]',source)
        # No cause infers product validity, cancellation or a different deadline.
        for expected in ['OutputLimit','IncompleteUtf8','InvalidUtf8','MissingPathMarker',
                         'InvalidPath','InvalidChallenge','Deadline','ChildExit']:
            self.assertIn(expected,variants)

    def test_harness_failure_reasons_are_closed_and_payload_free(self):
        name=output.TESTS['full'][0]
        for reason in output.HARNESS_FAILURE_REASONS:
            line=self.failure('none',reason)
            self.assertTrue(output.safe_failure(line))
            self.assertEqual(output.public_line(line.encode(),name),('failure',line))
        for reason in ['', 'Unknown', 'outputlimit', 'OutputLimit/private',
                       'OutputLimit private', 'OutputLimit\nprivate', 'OutputLimit:12']:
            self.assertFalse(output.safe_failure(self.failure('none',reason)))
        line=self.failure('none','OutputLimit')
        for invalid in [line+' private', 'private '+line,
                        line.replace(' reason=OutputLimit',''),
                        line.replace('reason=OutputLimit','reason=OutputLimit reason=Deadline')]:
            self.assertIsNone(output.public_line(invalid.encode(),name))

    def test_closed_failure_labels_and_canonical_errno(self):
        for summary in ['none','FullCurrentDispatch:Begin',
                        'SingleIpcBind:IoKind=PermissionDenied:errno=1',
                        'SingleIpcBind:IoKind=Other:errno=-2147483648']:
            self.assertTrue(output.safe_failure(self.failure(summary)))
        for summary in ['private:Begin','SingleIpcBind:private',
                        'SingleIpcBind:IoKind=Other:errno=+1',
                        'SingleIpcBind:IoKind=Other:errno=2147483648',
                        'SingleIpcBind:IoKind=Other:errno=-0',
                        ','.join(['FullCurrentDispatch:Begin']*65)]:
            self.assertFalse(output.safe_failure(self.failure(summary)))
        self.assertFalse(output.safe_failure(self.failure().replace('Some(101)','Some(2147483648)')))
        self.assertFalse(output.safe_failure(self.failure().replace('inputs=1/2','inputs=3/2')))

    def test_single_worker_diagnostics_remain_closed_and_payload_free(self):
        labels=sorted(label for label in output.BOUNDARIES if label.startswith('SingleWork'))
        self.assertEqual(len(labels),26)
        for label in labels:
            self.assertTrue(output.safe_failure(self.failure(label+':Begin')))
            self.assertTrue(output.safe_failure(self.failure(label+':SignerAuthentication')))
        for summary in ['SingleWorkUnknown:Begin',
                        'SingleWorkPrepareReentry:SignerAuthentication private-data',
                        'SingleWorkPrepareWitness:SignerAuthentication:private-data',
                        'SingleWorkCommitAcquire:private-data']:
            self.assertFalse(output.safe_failure(self.failure(summary)))
        line=self.failure('SingleWorkPrepareReentry:SignerAuthentication')
        self.assertFalse(output.safe_failure(line+' private-data'))

    def test_retained_preparation_diagnostics_are_exact_and_payload_free(self):
        labels = {
            'FullOriginalPolicy', 'RetainedPredecessor', 'RetainedMaterial',
            'RetainedEconomics', 'RetainedInvocation', 'RetainedRuntime',
            'RetainedProvider', 'RetainedTls', 'RetainedWitness',
            'RetainedPolicyRead', 'RetainedPolicyMatch', 'RetainedSelectionFiles',
            'ContinuedPredecessor', 'ContinuedObservation', 'ContinuedOriginal',
            'ContinuedWait', 'ContinuedPrepare',
        }
        self.assertEqual(len(labels),17)
        selected={label for label in output.BOUNDARIES
                  if label.startswith(('Retained','Continued')) or label=='FullOriginalPolicy'}
        self.assertEqual(selected,labels)
        for label in labels:
            for result in ['Begin','Complete','HostAuthentication','HostReceipt']:
                self.assertTrue(output.safe_failure(self.failure(label+':'+result)))
        for value in ['RetainedUnknown:Begin','ContinuedUnknown:HostReceipt',
                      'RetainedPolicyRead:HostReceipt private-data',
                      'ContinuedObservation:HostAuthentication:private-data',
                      'FullOriginalPolicy:private-data']:
            self.assertFalse(output.safe_failure(self.failure(value)))
        self.assertFalse(output.safe_failure(self.failure('RetainedMaterial:HostReceipt')+' private-data'))

    def test_roster_phase_diagnostics_are_exact_closed_kinds(self):
        root=ROOT/'crates/wholepact-native-host/src/host'
        text=(root/'synthetic_roster_trace_v1.rs').read_text()
        kinds={}
        for kind in ['Phase','Outcome']:
            body=re.search(r'labels! \{ '+kind+r' \{(.*?)\} \}',text,re.S).group(1)
            kinds[kind]=set(x.strip() for x in body.split(',') if x.strip())
        self.assertEqual(len(kinds['Phase']),48)
        self.assertTrue(kinds['Phase'] <= output.BOUNDARIES)
        self.assertTrue(kinds['Outcome'] <= output.OUTCOMES)
        signer=ROOT/'crates/wholepact-signer/src/native_ui/born_manual_roster_v2/synthetic_diagnostics.rs'
        labels=set(re.findall(r'=> "(Roster\w+)"',signer.read_text()))
        self.assertEqual(len(labels),53)
        self.assertTrue(labels <= output.BOUNDARIES)
        for label in labels | kinds['Phase']:
            self.assertTrue(output.safe_failure(self.failure(label+':Begin')))
            self.assertTrue(output.safe_failure(self.failure(label+':HostInvalid')))
        for outcome in kinds['Outcome']:
            self.assertTrue(output.safe_failure(self.failure('InventorySynchronize:'+outcome)))
        for value in ['RosterWorkUnknown:Begin','InventoryUnknown:Begin',
                      'InventorySynchronize:SyncUnknown','RosterClearOwner:SignerLocked private',
                      'InventorySynchronize:ChainBackendFailure:private',
                      'InventorySynchronize:private']:
            self.assertFalse(output.safe_failure(self.failure(value)))
        self.assertFalse(output.safe_failure(self.failure('RosterClearPeer:Begin')+' private'))

    def test_lower_error_preflight_is_one_exact_inert_case(self):
        expected='host::synthetic_roster_trace_v1::lower_error_projection_preserves_only_closed_kinds'
        self.assertEqual(output.LOWER_ERROR_TESTS,(expected,))
        root=ROOT/'crates/wholepact-native-host/src'
        self.assertIn('mod synthetic_roster_trace_v1;', (root/'host.rs').read_text())
        self.assertEqual((root/'host/synthetic_roster_trace_v1.rs').read_text().count(
            'fn lower_error_projection_preserves_only_closed_kinds()'),1)
        combined=output.PURE_TESTS+output.POLICY_ENVELOPE_TESTS+output.PROMPT_RENDERING_TESTS+output.LOWER_ERROR_TESTS
        self.assertEqual(len(set(combined)),24)
        self.assertNotIn(expected,[row[0] for row in output.TESTS.values()])
        self.assertNotEqual(expected,output.STORAGE_BOOTSTRAP_TEST)

    def test_inventory_denials_are_exact_closed_predicates(self):
        host=ROOT/'crates/wholepact-native-host/src/host/synthetic_roster_trace_v1.rs'
        body=re.search(r'labels! \{ Phase \{(.*?)\} \}',host.read_text(),re.S).group(1)
        host_labels={x.strip() for x in body.split(',') if x.strip().startswith('Scan')}
        signer=ROOT/'crates/wholepact-signer/src/account/birth/enrollment/roster_v2/inventory/synthetic_denial.rs'
        signer_labels=set(re.findall(r'=> "(Inventory\w+)"',signer.read_text()))
        self.assertEqual(len(host_labels),19)
        self.assertEqual(len(signer_labels),27)
        self.assertEqual(len(host_labels|signer_labels),46)
        self.assertTrue(host_labels|signer_labels <= output.BOUNDARIES)
        for label in host_labels|signer_labels:
            for outcome in ['HostPermission','SignerReviewMismatch','SignerAuthentication']:
                self.assertTrue(output.safe_failure(self.failure(label+':'+outcome)))
        for item in ['ScanNativeUnknown:HostPermission','InventoryObservedUnknown:SignerReviewMismatch',
                     'ScanAccessAccount:HostPermission private','InventorySourceOwner:SignerLocked:private']:
            self.assertFalse(output.safe_failure(self.failure(item)))
        self.assertFalse(output.safe_failure(self.failure('InventoryObservedAgeExpired:SignerReviewMismatch')+' private'))

    def test_native_lease_origin_diagnostics_expose_only_closed_kinds(self):
        source=ROOT/'crates/wholepact-signer/src/authority_bridge/manual_roster_inventory_v2.rs'
        labels=set(re.findall(r'"(Origin\w+)"',source.read_text()))
        self.assertEqual(len(labels),23)
        self.assertEqual(labels,{name for name in output.OUTCOMES if name.startswith('Origin')})
        self.assertIn('InventoryLeaseOrigin',output.BOUNDARIES)
        for label in labels:
            self.assertTrue(output.safe_failure(self.failure('InventoryLeaseOrigin:'+label)))
        for value in ['InventoryLeaseOrigin:OriginUnknown',
                      'InventoryLeaseOrigin:OriginIoTimedOut private',
                      'InventoryLeaseOrigin:OriginIoOther:private',
                      'InventoryLeaseUnknown:OriginPermission']:
            self.assertFalse(output.safe_failure(self.failure(value)))
        self.assertFalse(output.safe_failure(self.failure('InventoryLeaseOrigin:OriginPermission')+' private'))

    def test_denial_preflight_is_one_exact_inert_case(self):
        expected='host::synthetic_roster_trace_v1::denial_projection_preserves_single_evaluation_and_short_circuit'
        self.assertEqual(output.DENIAL_TESTS,(expected,))
        source=ROOT/'crates/wholepact-native-host/src/host/synthetic_roster_trace_v1.rs'
        self.assertEqual(source.read_text().count('fn '+expected.rsplit('::',1)[1]+'()'),1)
        combined=output.PURE_TESTS+output.POLICY_ENVELOPE_TESTS+output.PROMPT_RENDERING_TESTS+output.LOWER_ERROR_TESTS+output.DENIAL_TESTS
        self.assertEqual(len(combined),25)
        self.assertEqual(len(set(combined)),25)
        self.assertNotIn(expected,[row[0] for row in output.TESTS.values()])
        self.assertNotEqual(expected,output.STORAGE_BOOTSTRAP_TEST)

    def test_projection_does_not_search_inside_private_text(self):
        name=output.TESTS['initial'][0]
        marker=self.failure()
        self.assertEqual(output.public_line(marker.encode(),name),('failure',marker))
        self.assertEqual(output.public_line(('test '+name+' ... '+marker).encode(),name),('failure',marker))
        for value in ['private '+marker,'test unknown ... '+marker,marker+' private','private wallet bytes']:
            self.assertIsNone(output.public_line(value.encode(),name))
        self.assertIsNone(output.public_line(b'x'*8193,name))

    def test_failure_enum_sets_match_compiled_source(self):
        path=ROOT/'crates/wholepact-native-host/src/host/manual_enrollment/command/roster_publication_v2/sequential_construction_v3_qualification/safe_diagnostics_v1.rs'
        text=path.read_text()
        for kind,expected in [('Boundary',output.BOUNDARIES),('Outcome',output.OUTCOMES)]:
            body=re.search(r'labels! \{ '+kind+r' \{(.*?)\} \}',text,re.S).group(1)
            self.assertEqual(frozenset(x.strip() for x in body.split(',') if x.strip()),expected)

    def test_oversized_physical_line_never_promotes_its_marker_suffix(self):
        framing=output.BoundedLines()
        marker=self.failure().encode()
        self.assertEqual(framing.feed(b'private'+b'x'*8193),[])
        self.assertEqual(framing.feed(marker),[])
        self.assertEqual(framing.feed(b'\n'),[])
        self.assertEqual(framing.feed(marker+b'\n'),[marker])
        # Also reject a single oversized complete chunk and resume next line.
        self.assertEqual(framing.feed(b'x'*8193+marker+b'\n'+marker+b'\n'),[marker])

    def test_rolling_preflight_is_ten_exact_pure_parser_cases(self):
        base=ROOT/'crates/wholepact-native-host/src/host/manual_enrollment/command/roster_publication_v2'
        source=(base/'sequential_construction_v3_qualification/rolling_transcript_v1.rs').read_text()
        names=re.findall(r'#\[test\]\s+(?:#\[cfg\(feature = "synthetic-born-joined-qualification"\)\]\s+)?fn (\w+)\(',source)
        expected=tuple(output.PREFIX+'rolling_transcript_v1::tests::'+name for name in names)
        self.assertEqual(len(expected),10)
        self.assertEqual(expected,output.ROLLING_TRANSCRIPT_TESTS)
        self.assertIn('#[path = "sequential_construction_v3_qualification/rolling_transcript_v1.rs"]\nmod rolling_transcript_v1;',
                      (base/'sequential_construction_v3_qualification.rs').read_text())
        combined=output.PURE_TESTS+output.POLICY_ENVELOPE_TESTS+output.PROMPT_RENDERING_TESTS+output.LOWER_ERROR_TESTS+output.DENIAL_TESTS+expected
        self.assertEqual(len(combined),35)
        self.assertEqual(len(set(combined)),35)
        for name in expected:
            self.assertNotIn(name,[row[0] for row in output.TESTS.values()])
            self.assertNotEqual(name,output.STORAGE_BOOTSTRAP_TEST)
            self.assertNotIn(name,output.SIGNER_VALIDATION_TESTS+output.SIGNER_BOOKKEEPING_TESTS)

    def test_witness_diagnostics_use_exact_closed_authority_projection(self):
        source=(ROOT/'crates/wholepact-authority/src/native_witness_owner/window/synthetic_plan_diagnostics_v1.rs').read_text()
        labels=set(re.findall(r'Self::(WitnessPlan\w+) => "WitnessPlan\w+"',source))
        outcomes=set(re.findall(r'"(Authority\w+)"',source))
        self.assertEqual(len(labels),15)
        self.assertEqual(len(outcomes),26)
        self.assertEqual(labels,{x for x in output.BOUNDARIES if x.startswith('WitnessPlan')})
        self.assertEqual(outcomes,{x for x in output.OUTCOMES if x.startswith('Authority')})
        kinds=dict(re.findall(r'AuthorityError::(\w+) => "(Authority\w+)"',source))
        host=(ROOT/'crates/wholepact-native-host/src/host/manual_enrollment/command/roster_publication_v2/sequential_construction_v3_qualification/safe_diagnostics_v1.rs').read_text()
        self.assertEqual(len(kinds),23)
        for variant,label in kinds.items():
            self.assertEqual(label,'Authority'+variant)
            self.assertIn('E::'+variant+' => Outcome::'+label,host)
        for boundary in labels|{'ObservedPlanWitnessOrigin'}:
            for outcome in outcomes:
                self.assertTrue(output.safe_failure(self.failure(boundary+':'+outcome)))
        for value in ['WitnessPlanUnknown:AuthorityPermission','WitnessPlanInput:262145',
                      'WitnessPlanInput:AuthorityInputWithinBound private',
                      'WitnessPlanWorkerPrepare:AuthorityUnknown',
                      'ObservedPlanWitnessOrigin:AuthorityStorage:private']:
            self.assertFalse(output.safe_failure(self.failure(value)))

    def test_authority_projection_preflight_is_one_exact_inert_case(self):
        expected=output.PREFIX+'safe_diagnostics_v1::authority_error_projection_preserves_only_closed_variants'
        self.assertEqual(output.AUTHORITY_PROJECTION_TESTS,(expected,))
        source=ROOT/'crates/wholepact-native-host/src/host/manual_enrollment/command/roster_publication_v2/sequential_construction_v3_qualification/safe_diagnostics_v1.rs'
        self.assertEqual(source.read_text().count('fn '+expected.rsplit('::',1)[1]+'()'),1)
        combined=output.PURE_TESTS+output.POLICY_ENVELOPE_TESTS+output.PROMPT_RENDERING_TESTS+output.LOWER_ERROR_TESTS+output.DENIAL_TESTS+output.ROLLING_TRANSCRIPT_TESTS+output.AUTHORITY_PROJECTION_TESTS
        self.assertEqual(len(combined),36)
        self.assertEqual(len(set(combined)),36)
        self.assertNotIn(expected,[row[0] for row in output.TESTS.values()])
        self.assertNotEqual(expected,output.STORAGE_BOOTSTRAP_TEST)
        self.assertNotIn(expected,output.SIGNER_VALIDATION_TESTS+output.SIGNER_BOOKKEEPING_TESTS)

    def test_pure_preflight_is_exactly_the_eighteen_reviewed_cases(self):
        base=ROOT/'crates/wholepact-native-host/src/host/manual_enrollment/command/roster_publication_v2/sequential_construction_v3_qualification'
        expected=[]
        for leaf in ['owned_test_process_group_v1','owned_tls_child_v1','process_containment_v1','public_outcome_v1']:
            module='tests' if leaf=='public_outcome_v1' else 'pure_tests'
            names=re.findall(r'#\[test\]\s+fn (\w+)\(', (base/(leaf+'.rs')).read_text())
            # This helper is a child of the provider TLS module, not qualification.
            scope='synthetic_provider_tls_v1::owned_tls_child_v1' if leaf=='owned_tls_child_v1' else leaf
            expected.extend(output.PREFIX+scope+'::'+module+'::'+name for name in names)
            if leaf=='owned_tls_child_v1':
                self.assertIn('mod owned_tls_child_v1;', (base/'synthetic_provider_tls_v1.rs').read_text())
        self.assertEqual(len(expected),18)
        self.assertEqual(tuple(expected),output.PURE_TESTS)
        self.assertNotIn(output.TESTS['initial'][0],expected)
        self.assertNotIn(output.TESTS['full'][0],expected)

    def test_policy_preflight_is_three_exact_inert_envelope_cases(self):
        base=ROOT/'crates/wholepact-native-host/src/host/manual_enrollment/command/roster_publication_v2/sequential_construction_v3_qualification'
        names=re.findall(r'#\[test\]\s+fn (\w+)\(', (base/'original_policy_export_v2.rs').read_text())
        expected=tuple(output.PREFIX+'retained_joined_v3::original_policy_export_v2::tests::'+name for name in names)
        self.assertEqual(len(expected),3)
        self.assertEqual(expected,output.POLICY_ENVELOPE_TESTS)
        self.assertIn('#[path = "original_policy_export_v2.rs"]\nmod original_policy_export_v2;', (base/'retained_joined_v3.rs').read_text())
        combined=output.PURE_TESTS+output.POLICY_ENVELOPE_TESTS
        self.assertEqual(len(set(combined)),21)
        for name in output.POLICY_ENVELOPE_TESTS:
            self.assertNotIn(name,output.PURE_TESTS)
            self.assertNotIn(name,[row[0] for row in output.TESTS.values()])
            self.assertNotEqual(name,output.STORAGE_BOOTSTRAP_TEST)

    def test_prompt_preflight_is_two_exact_no_terminal_rendering_cases(self):
        parent=ROOT/'crates/wholepact-native-host/src/host/manual_enrollment/command/roster_publication_v2/sequential_construction_v3_qualification.rs'
        text=parent.read_text()
        names=['finite_prompt_rendering_preserves_exact_terminal_purpose',
               'full_finite_prompt_census_uses_only_exact_rendered_expectations']
        self.assertEqual(tuple(output.PREFIX+name for name in names),output.PROMPT_RENDERING_TESTS)
        for name in names:
            self.assertEqual(len(re.findall(r'fn '+name+r'\(\)',text)),1)
        combined=output.PURE_TESTS+output.POLICY_ENVELOPE_TESTS+output.PROMPT_RENDERING_TESTS
        self.assertEqual(len(set(combined)),23)
        for name in output.PROMPT_RENDERING_TESTS:
            self.assertNotIn(name,output.PURE_TESTS+output.POLICY_ENVELOPE_TESTS)
            self.assertNotIn(name,[row[0] for row in output.TESTS.values()])
            self.assertNotEqual(name,output.STORAGE_BOOTSTRAP_TEST)

    def test_storage_bootstrap_is_separate_exact_maintained_encrypted_case(self):
        name=output.STORAGE_BOOTSTRAP_TEST
        self.assertEqual(name,'recovery_generation::layered::tests::native_layered_current_eight_nine_parent_provenance_is_exact_and_not_relabelable')
        self.assertNotIn(name,output.PURE_TESTS)
        path=ROOT/'crates/wholepact-native-host/src/recovery_generation/layered/tests.rs'
        self.assertEqual(path.read_text().count('fn '+name.rsplit('::',1)[1]+'()'),1)

    def test_signer_validation_is_four_exact_private_crypto_cases(self):
        names=(
            'account::birth::retired_historical_tests::birth_identity_one_derivation_preserves_both_original_commitments',
            'account::birth::active::tests::borrowed_original_plaintext_matches_complete_decoder_and_refuses_substitution',
            'account::birth::active::tests::borrowed_original_is_exact_vault_scoped_and_checks_fresh_ciphertexts',
            'account::birth::active::tests::borrowed_original_cannot_be_issued_for_mismatched_held_origin',
        )
        self.assertEqual(output.SIGNER_VALIDATION_TESTS,names)
        root=ROOT/'crates/wholepact-signer/src'
        self.assertIn('mod birth;', (root/'account.rs').read_text())
        birth=(root/'account/birth.rs').read_text()
        self.assertIn('mod active;',birth)
        self.assertIn('mod retired_historical_tests {',birth)
        active=(root/'account/birth/active.rs').read_text()
        self.assertIn('mod tests {',active)
        for name in names:
            source=birth if 'retired_historical_tests' in name else active
            self.assertEqual(len(re.findall(r'#\[test\]\s+fn '+name.rsplit('::',1)[1]+r'\(',source)),1)
            self.assertNotIn(name,output.PURE_TESTS+output.POLICY_ENVELOPE_TESTS+output.PROMPT_RENDERING_TESTS+output.LOWER_ERROR_TESTS+output.DENIAL_TESTS)
        shell=(ROOT/'scripts/ci-synthetic-linux.sh').read_text()
        build='timeout --signal=TERM --kill-after=30s 1200s rustup run 1.99.0 cargo test --locked --release -p wholepact-signer --all-features --lib --no-run --message-format=json'
        self.assertEqual(shell.count(build),1)
        self.assertIn("get('name')=='wholepact_signer'",shell)
        selected='python3 -B scripts/ci-synthetic-output.py "$signer_executable" signer-validation'
        self.assertEqual(shell.count(selected),1)
        self.assertLess(shell.index(build),shell.index(selected))
        self.assertLess(shell.index(selected),shell.index('"$executable" initial'))

    def test_signer_validation_runs_only_exact_bounded_cases_and_withholds_output(self):
        calls=[]
        def fake_run(argv, **kwargs):
            calls.append((argv,kwargs))
            name=argv[2]
            self.assertIn(name,output.SIGNER_VALIDATION_TESTS+output.SIGNER_BOOKKEEPING_TESTS)
            self.assertEqual(argv[:2],['/verified/signer','--exact'])
            self.assertEqual(argv[3],'--test-threads=1')
            if argv[-1]=='--list':
                self.assertEqual(len(argv),5)
                self.assertEqual(kwargs,dict(capture_output=True,timeout=30,check=True))
                return output.subprocess.CompletedProcess(argv,0,(name+': test\n\n1 test, 0 benchmarks\n').encode(),b'')
            self.assertEqual(len(argv),4)
            self.assertEqual(kwargs,dict(stdout=output.subprocess.PIPE,stderr=output.subprocess.STDOUT,timeout=120))
            return output.subprocess.CompletedProcess(argv,0,b'private synthetic output')
        captured=io.StringIO()
        with mock.patch.object(output.resource,'getrlimit',return_value=(0,0)), \
             mock.patch.object(output.subprocess,'run',side_effect=fake_run), \
             contextlib.redirect_stdout(captured):
            output.run_signer_validation('/verified/signer')
        self.assertEqual([argv[2] for argv,_ in calls], [name for name in output.SIGNER_VALIDATION_TESTS+output.SIGNER_BOOKKEEPING_TESTS for _ in range(2)])
        self.assertEqual(captured.getvalue(),'CI_SYNTHETIC_SIGNER_VALIDATION passed=6 crypto_file_cases=4 bookkeeping_cases=2 native_payment_verified=false raw_output_discarded=true\n')

    def test_signer_bookkeeping_preflight_is_two_exact_private_state_cases(self):
        prefix='account::birth::enrollment::roster_v2::inventory::'
        expected=(
            prefix+'tests::challenge_bookkeeping_requires_successful_checked_send_first',
            prefix+'candidate::tests::candidate_nonce_is_retained_only_after_fully_checked_send_success',
        )
        self.assertEqual(output.SIGNER_BOOKKEEPING_TESTS,expected)
        root=ROOT/'crates/wholepact-signer/src/account/birth/enrollment/roster_v2'
        inventory=(root/'inventory.rs').read_text()
        candidate=(root/'inventory/candidate.rs').read_text()
        self.assertIn('mod candidate;',inventory)
        for name,text in zip(expected,(inventory,candidate)):
            self.assertIn('mod tests {',text)
            self.assertEqual(len(re.findall(r'#\[test\]\s+fn '+name.rsplit('::',1)[1]+r'\(',text)),1)
            self.assertNotIn(name,output.SIGNER_VALIDATION_TESTS)
        self.assertEqual(len(set(output.SIGNER_VALIDATION_TESTS+expected)),6)

    def test_candidate_retention_diagnostics_add_only_six_closed_labels(self):
        expected={'CandidateRetainCurrent','CandidateRetainRequest','CandidateRetainBegin',
                  'CandidateRetainFinish','CandidateLeaseOrigin','CandidateRequestRemaining'}
        self.assertTrue(expected <= output.BOUNDARIES)
        for label in expected:
            for result in ['Begin','Complete','HostPermission','SignerReviewMismatch','OriginIoWouldBlock']:
                self.assertTrue(output.safe_failure(self.failure(label+':'+result)))
        for item in ['CandidateRetainUnknown:HostPermission','CandidateLeaseOrigin:OriginUnknown',
                     'CandidateRequestRemaining:SignerReviewMismatch private',
                     'CandidateRetainCurrent:HostPermission:private']:
            self.assertFalse(output.safe_failure(self.failure(item)))
        self.assertFalse(output.safe_failure(self.failure('CandidateLeaseOrigin:OriginIoWouldBlock')+' private'))
        source=(ROOT/'crates/wholepact-signer/src/account/birth/enrollment/roster_v2/inventory/synthetic_denial.rs').read_text()
        self.assertEqual(set(re.findall(r'=> "(Candidate\w+)"',source)),{'CandidateRequestRemaining'})

    def test_signer_validation_missing_failed_or_timed_out_is_not_success(self):
        name=output.SIGNER_VALIDATION_TESTS[0]
        listed=output.subprocess.CompletedProcess([],0,(name+': test\n\n1 test, 0 benchmarks\n').encode(),b'')
        cases=[
            [output.subprocess.CompletedProcess([],0,b'0 tests, 0 benchmarks\n',b'')],
            [output.subprocess.CompletedProcess([],0,listed.stdout,b'private error')],
            [listed,output.subprocess.CompletedProcess([],101,b'private panic')],
            [listed,output.subprocess.CompletedProcess([],0,b'x'*(1024*1024+1))],
            [listed,output.subprocess.TimeoutExpired('private command',120,output=b'private output')],
        ]
        for results in cases:
            captured=io.StringIO()
            with mock.patch.object(output.resource,'getrlimit',return_value=(0,0)), \
                 mock.patch.object(output.subprocess,'run',side_effect=results) as run, \
                 contextlib.redirect_stdout(captured):
                with self.assertRaises(Exception): output.run_signer_validation('/verified/signer')
            self.assertLessEqual(run.call_count,2)
            self.assertEqual(captured.getvalue(),'CI_SYNTHETIC_SIGNER_VALIDATION failed_test='+name+' raw_output_withheld=true\n')

    def test_ci_temporary_socket_path_budget(self):
        # Includes this runner's extra short TMPDIR layer, not merely /tmp.
        for inner in ['wholepact-born-manual-ipc-','wholepact-born-stop-','.tmp']:
            path='/tmp/wpc.aaaaaa/wp-pty-bbbbbb/'+inner+'cccccc/requests-'+'0'*24+'.sock'
            self.assertLess(len(path.encode()),108)

class PublicCompilerOutputTests(unittest.TestCase):
    source='crates/wholepact-signer/src/account/birth/enrollment/roster_v2/inventory/candidate.rs'
    def diagnostic(self, **span_changes):
        span={'file_name':self.source,'is_primary':True,'line_start':63,'line_end':66,
              'text':[{'text':'private source contents never printed'}],
              'label':'private compiler label'}
        span.update(span_changes)
        return {'reason':'compiler-message','message':{'level':'error','code':{'code':'E0433','explanation':'private explanation'},
                'message':'private diagnostic','rendered':'private rendered text','spans':[span]}}

    def project(self, row):
        return build_errors.project(row,frozenset((self.source,)),ROOT)

    def test_compiler_projection_only_public_code_path_and_lines(self):
        expected=[{'code':'E0433','source':self.source,'line_start':63,'line_end':66}]
        self.assertEqual(self.project(self.diagnostic()),expected)
        self.assertEqual(self.project(self.diagnostic(file_name=str(ROOT/self.source))),expected)
        self.assertNotIn('private',json.dumps(expected))

    def test_compiler_projection_never_emits_untracked_or_private_paths(self):
        for name in ['/tmp/private-wallet.rs','crates/unknown/src/private.rs',
                     'crates/wholepact-signer/../private.rs',self.source+'\nprivate',
                     'https://example.invalid/private.rs']:
            item=self.project(self.diagnostic(file_name=name))
            self.assertEqual(item,[{'code':'E0433','source':None,'line_start':None,'line_end':None}])
        for changes in [{'line_start':True},{'line_start':0},{'line_end':62},
                        {'line_end':10_000_001},{'is_primary':False}]:
            self.assertIsNone(self.project(self.diagnostic(**changes))[0]['source'])

    def test_compiler_projection_handles_uncoded_errors_without_message(self):
        for code in [None,{'code':'private'}, {'code':'E0433 private'}, {'code':123}]:
            row=self.diagnostic(); row['message']['code']=code
            actual=self.project(row)
            self.assertEqual(actual[0]['code'],'Uncoded')
            self.assertNotIn('private',json.dumps(actual))
        for row in [None,[],{}, {'reason':'build-script-executed'},
                    {'reason':'compiler-message','message':None}]:
            self.assertEqual(self.project(row),[])
        row=self.diagnostic(); row['message']['level']='warning'
        self.assertEqual(self.project(row),[])

    def test_compiler_scan_discards_oversize_physical_line_suffix(self):
        valid=json.dumps(self.diagnostic()).encode()+b'\n'
        with mock.patch.object(build_errors,'MAX_LINE',1024):
            raw=b'private'+b'x'*1025+valid+valid
            rows,truncated=build_errors.scan(io.BytesIO(raw),frozenset((self.source,)),ROOT)
        self.assertTrue(truncated)
        self.assertEqual(rows,self.project(self.diagnostic()))

    def test_compiler_scan_caps_locations_bytes_and_deduplicates(self):
        valid=json.dumps(self.diagnostic()).encode()+b'\n'
        rows,truncated=build_errors.scan(io.BytesIO(valid*2),frozenset((self.source,)),ROOT)
        self.assertEqual(len(rows),1); self.assertFalse(truncated)
        many=b''.join(json.dumps(self.diagnostic(line_start=n,line_end=n)).encode()+b'\n' for n in range(1,30))
        rows,truncated=build_errors.scan(io.BytesIO(many),frozenset((self.source,)),ROOT)
        self.assertEqual(len(rows),20); self.assertTrue(truncated)
        with mock.patch.object(build_errors,'MAX_BYTES',16):
            rows,truncated=build_errors.scan(io.BytesIO(valid),frozenset((self.source,)),ROOT)
        self.assertEqual(rows,[]); self.assertTrue(truncated)

    def test_compiler_source_inventory_uses_only_tracked_rust_paths(self):
        result=output.subprocess.CompletedProcess([],0,(self.source+'\0private/secret.rs\0crates/a/../secret.rs\0').encode(),b'')
        with mock.patch.object(build_errors.subprocess,'run',return_value=result) as run:
            self.assertEqual(build_errors.public_sources(ROOT),frozenset((self.source,)))
        run.assert_called_once_with(['git','-C',str(ROOT),'ls-files','-z','--','crates'],capture_output=True,timeout=10,check=True)

    def test_both_build_failures_keep_original_status_and_never_fallback(self):
        shell=(ROOT/'scripts/ci-synthetic-linux.sh').read_text()
        for phase,filename,seconds,package in [('host','build-metadata.jsonl',3600,'wholepact-native-host'),
                                               ('signer','signer-build-metadata.jsonl',1200,'wholepact-signer')]:
            start=f'if timeout --signal=TERM --kill-after=30s {seconds}s rustup run 1.99.0 cargo test --locked --release -p {package} --all-features --lib --no-run --message-format=json > "$build_root/{filename}"; then'
            self.assertEqual(shell.count(start),1)
            body=shell[shell.index(start):].split('\nfi',1)[0]
            self.assertIn('else\n  build_status=$?\n',body)
            self.assertIn(f'python3 -B scripts/ci-synthetic-build-errors.py "$build_root/{filename}" {phase} || true\n  exit "$build_status"',body)

if __name__=='__main__':
    unittest.main()
