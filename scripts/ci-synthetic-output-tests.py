#!/usr/bin/env python3
"""Pure public parser/selection tests. No child, socket, key or wallet is created."""
import importlib.util
import hashlib
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
    def test_durable_owner_reopen_is_an_exact_ignored_distinct_phase(self):
        name,seconds,flags=output.phase_selection('durable-owner-reopen')
        self.assertEqual(name,output.PREFIX+'durable_proposal_v1::durable_proposal_native_owner_reopen_retains_exact_fixed_proof')
        self.assertEqual(seconds,1080)
        self.assertEqual(flags,['--exact',name,'--test-threads=1','--ignored'])
        self.assertNotEqual(name,output.TESTS['full'][0])
        self.assertNotIn('--ignored',output.phase_selection('initial')[2])
        with self.assertRaises(KeyError): output.phase_selection('arbitrary')

    def test_durable_fixed_signing_is_exact_ignored_and_preserves_bounds(self):
        name,seconds,flags=output.phase_selection('durable-fixed-signing')
        self.assertEqual(name,output.PREFIX+'durable_proposal_v1::durable_proposal_native_fixed_signing_retains_exact_results')
        self.assertEqual(seconds,1080)
        self.assertEqual(flags,['--exact',name,'--test-threads=1','--ignored'])
        self.assertNotEqual(name,output.TESTS['durable-owner-reopen'][0])
        shell=(ROOT/'scripts/ci-durable-native-linux.sh').read_text()
        call='python3 -B scripts/ci-synthetic-output.py "$executable" durable-fixed-signing'
        self.assertEqual(shell.count(call),1)
        workflow=(ROOT/'.github/workflows/durable-native-linux.yml').read_text()
        self.assertIn('timeout-minutes: 150',workflow)

    def test_durable_runner_does_not_claim_full_payment_or_process_restart(self):
        shell=(ROOT/'scripts/ci-durable-native-linux.sh').read_text()
        workflow=(ROOT/'.github/workflows/durable-native-linux.yml').read_text()
        self.assertIn('refs/heads/qualification/durable-proposal-v1',shell)
        self.assertIn('branches: [qualification/durable-proposal-v1]',workflow)
        self.assertIn('python3 -B scripts/ci-synthetic-output.py "$executable" durable-owner-reopen',shell)
        self.assertNotIn('python3 -B scripts/ci-synthetic-output.py "$executable" full',shell)
        self.assertIn('no OS-process restart, public-chain settlement',shell)

    def test_durable_entry_failure_stages_remain_closed_and_redacted(self):
        self.assertEqual(len(output.DURABLE_ENTRY_BOUNDARIES),14)
        for label in output.DURABLE_ENTRY_BOUNDARIES:
            self.assertTrue(output.safe_failure(self.failure(label+':Begin')))
            self.assertTrue(output.safe_failure(self.failure(label+':SignerRecoveryRequired')))
            self.assertFalse(output.safe_failure(self.failure(label+':private-account-id')))
        self.assertFalse(output.safe_failure(self.failure('DurableEntryUnreviewedStage:Begin')))
        self.assertFalse(output.safe_failure(self.failure('DurableEntryVaultOpen:/private/vault')))

    def test_durable_host_first_failure_stages_remain_closed_and_redacted(self):
        self.assertEqual(len(output.DURABLE_HOST_BOUNDARIES),23)
        for label in output.DURABLE_HOST_BOUNDARIES:
            self.assertTrue(output.safe_failure(self.failure(label+':Begin')))
            self.assertFalse(output.safe_failure(self.failure(label+':private-account-id')))
            self.assertFalse(output.safe_failure(self.failure(label+':/private/vault')))
        self.assertFalse(output.safe_failure(self.failure('DurableHostUnreviewedStage:Begin')))

    def test_durable_financial_stages_remain_closed_and_redacted(self):
        self.assertEqual(len(output.DURABLE_FINANCIAL_BOUNDARIES),13)
        self.assertFalse(output.DURABLE_FINANCIAL_BOUNDARIES & output.DURABLE_HOST_BOUNDARIES)
        for label in output.DURABLE_FINANCIAL_BOUNDARIES:
            self.assertTrue(output.safe_failure(self.failure(label+':Begin')))
            self.assertFalse(output.safe_failure(self.failure(label+':private-account-id')))
            self.assertFalse(output.safe_failure(self.failure(label+':/private/vault')))
        self.assertFalse(output.safe_failure(self.failure('DurableHostFinancialUnreviewed:Begin')))

    def test_durable_label_case_is_exact_pure_and_uses_maintained_validator(self):
        name='native_ui::runtime::durable_entry_v1::tests::durable_fixture_pairing_labels_use_existing_identifier_grammar'
        self.assertEqual(output.SIGNER_DURABLE_LABEL_TESTS,(name,))
        self.assertNotEqual(name,output.SIGNER_DURABLE_ENDPOINT_TEST)
        source=(ROOT/'crates/wholepact-signer/src/native_ui/runtime/durable_entry_v1.rs').read_text()
        self.assertIn('fn '+name.rsplit('::',1)[1]+'()',source)
        self.assertIn('review::validate_label',source)

    def test_durable_provider_metadata_uses_exact_data_only_selector(self):
        name=output.PREFIX+'synthetic_born_provider_v1::durable_metadata_tests::durable_provider_metadata_satisfies_actual_material_decoder'
        self.assertEqual(output.DURABLE_PROVIDER_METADATA_TEST,name)
        base=ROOT/'crates/wholepact-native-host/src/host/manual_enrollment/command/roster_publication_v2/sequential_construction_v3_qualification'
        source=(base/'synthetic_born_provider_v1/durable_metadata_tests.rs').read_text()
        self.assertIn('fn '+name.rsplit('::',1)[1]+'()',source)
        self.assertIn('HistoricalConstructionMaterialV1::decode',source)
        self.assertIn('mod durable_metadata_tests;', (base/'synthetic_born_provider_v1.rs').read_text())

    def test_durable_receipt_restrictions_are_exact_non_ipc_cases(self):
        self.assertEqual(len(output.SIGNER_DURABLE_RECEIPT_TESTS),5)
        self.assertEqual(len(set(output.SIGNER_DURABLE_RECEIPT_TESTS)),5)
        source=(ROOT/'crates/wholepact-signer/src/consent_journal/preconstruction_lease/durable_receipt_tests.rs').read_text()
        for name in output.SIGNER_DURABLE_RECEIPT_TESTS:
            self.assertIn('fn '+name.rsplit('::',1)[1]+'()',source)
            self.assertNotEqual(name,output.SIGNER_DURABLE_ENDPOINT_TEST)

    def test_durable_fail_fast_order_preserves_final_regression_gates(self):
        shell=(ROOT/'scripts/ci-durable-native-linux.sh').read_text()
        early=['python3 -B scripts/ci-synthetic-output-tests.py',
               'python3 -B scripts/ci-synthetic-output.py "$executable" pure',
               'python3 -B scripts/ci-synthetic-output.py "$executable" storage-bootstrap',
               'python3 -B scripts/ci-synthetic-output.py "$executable" durable-owner-reopen',
               'python3 -B scripts/ci-synthetic-output.py "$executable" durable-fixed-signing']
        positions=[shell.index('TMPDIR="$runtime_root" '+line) for line in early]
        self.assertEqual(positions,sorted(positions))
        signer_build=shell.index('cargo test --locked --release -p wholepact-signer ')
        authority_build=shell.index('cargo test --locked --release -p wholepact-authority ')
        self.assertLess(positions[-1],signer_build)
        self.assertLess(signer_build,authority_build)
        self.assertGreater(shell.index('export TMPDIR="$runtime_root"'),authority_build)
        final=shell.index('All listed regressions and synthetic-only')
        for later in ['python3 -B scripts/ci-synthetic-output.py "$signer_executable" signer-validation',
                      'python3 -B scripts/ci-synthetic-output.py "$authority_executable" authority-rendering']:
            self.assertEqual(shell.count(later),1)
            self.assertLess(authority_build,shell.index(later))
            self.assertLess(shell.index(later),final)
        self.assertIn('set -euo pipefail',shell)
        self.assertIn('trap finish EXIT',shell)

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
        self.assertEqual(len(kinds['Phase']),71)
        self.assertTrue(kinds['Phase'] <= output.BOUNDARIES)
        self.assertTrue(kinds['Outcome'] <= output.OUTCOMES)
        signer=ROOT/'crates/wholepact-signer/src/native_ui/born_manual_roster_v2/synthetic_diagnostics.rs'
        labels=set(re.findall(r'=> "(Roster\w+)"',signer.read_text()))
        self.assertEqual(len(labels),83)
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

    def test_completion_owner_and_witness_diagnostics_are_exact_closed_kinds(self):
        native=set("NativeOwnerRevoked NativeOwnerExpired NativeOwnerParent NativeOwnerRetirementParent".split())
        roster=set("RosterOwnerEpoch RosterWorkOpenCommonContext RosterWorkPrepareCompletionWitness RosterWorkPrepareReenteredConstruction RosterWorkCommitCompletionPair RosterWorkCommitCompletionWitness RosterWorkCommitCompletionClaim RosterWorkCommitReenteredConstruction RosterCompletionWitnessCheck RosterCompletionWitnessHistory RosterCompletionWitnessHistoryBinding RosterCompletionWitnessTransport".split())
        base=ROOT/'crates/wholepact-signer/src/native_ui'
        source=(base/'authority.rs').read_text()
        self.assertEqual(set(re.findall(r'=> "(NativeOwner\w+)"',source)),native)
        source=(base/'born_manual_roster_v2/synthetic_diagnostics.rs').read_text()
        actual=set(re.findall(r'=> "(Roster\w+)"',source))
        self.assertTrue(roster <= actual)
        self.assertEqual(len(native|roster),16)
        self.assertEqual({x for x in output.BOUNDARIES if x.startswith('NativeOwner')},native)
        self.assertTrue(native|roster <= output.BOUNDARIES)
        for label in native|roster:
            self.assertTrue(output.safe_failure(self.failure(label+':Begin')))
            self.assertFalse(output.safe_failure(self.failure(label+':Begin private-data')))
        for label in roster:
            for kind in ['Complete','SignerLocked','SignerUncertain','SignerReviewMismatch']:
                self.assertTrue(output.safe_failure(self.failure(label+':'+kind)))
        for value in ['NativeOwnerUnknown:Begin','RosterCompletionWitnessUnknown:SignerLocked',
                      'RosterWorkCommitCompletionUnknown:SignerUncertain',
                      'NativeOwnerExpired:private-data','RosterOwnerEpoch:Begin:private-data']:
            self.assertFalse(output.safe_failure(self.failure(value)))

    def test_completion_claim_and_channel_clock_are_closed_diagnostics(self):
        clocks=set("ConstructionClockTerminal ConstructionClockLiveness ConstructionClockWallRollback ConstructionClockWallExpired ConstructionClockMonotonicExpired".split())
        claims=set("RosterCompletionClaimCheck RosterCompletionClaimSign RosterCompletionClaimGranted RosterCompletionClaimClaim RosterCompletionClaimClaimed RosterCompletionClaimObserve RosterCompletionClaimHistory RosterCompletionClaimReentered RosterCompletionClaimSend".split())
        clock_source=(ROOT/'crates/wholepact-authority/src/construction_transport_client_v1.rs').read_text()
        self.assertEqual(set(re.findall(r'=> "(ConstructionClock\w+)"',clock_source)),clocks)
        signer=(ROOT/'crates/wholepact-signer/src/native_ui/born_manual_roster_v2/synthetic_diagnostics.rs').read_text()
        self.assertEqual(set(re.findall(r'=> "(RosterCompletionClaim\w+)"',signer)),claims)
        self.assertEqual({x for x in output.BOUNDARIES if x.startswith('ConstructionClock')},clocks)
        self.assertEqual({x for x in output.BOUNDARIES if x.startswith('RosterCompletionClaim')},claims)
        outcomes=set(re.findall(r'=> "(Authority\w+)"',signer))
        self.assertEqual(len(outcomes),23)
        self.assertEqual(outcomes,{x for x in output.OUTCOMES if x.startswith('Authority')}
                         - {'AuthorityInputEmpty','AuthorityInputWithinBound','AuthorityInputOverBound'})
        for label in clocks:
            self.assertTrue(output.safe_failure(self.failure(label+':Begin')))
        for label in claims:
            for kind in outcomes|{'Begin','Complete','SignerLocked','SignerUncertain'}:
                self.assertTrue(output.safe_failure(self.failure(label+':'+kind)))
        for value in ['ConstructionClockUnknown:Begin','ConstructionClockWallExpired:Begin 123',
                      'RosterCompletionClaimUnknown:AuthorityExpired',
                      'RosterCompletionClaimClaim:AuthorityUnknown',
                      'RosterCompletionClaimObserve:AuthorityUncertain private-data',
                      'RosterCompletionClaimHistory:AuthorityExpired:private-data']:
            self.assertFalse(output.safe_failure(self.failure(value)))

    def test_construction_effect_diagnostics_are_exact_and_payload_free(self):
        expected=set("RosterConstructionCheck RosterConstructionReserve RosterConstructionReservedAppend RosterConstructionConsume RosterConstructionConsumedAppend RosterConstructionSend RosterConstructionIntoNamed RosterConstructionNamedOwner RosterConstructionFinalOwner".split())
        source=(ROOT/'crates/wholepact-signer/src/native_ui/born_manual_roster_v2/synthetic_diagnostics.rs').read_text()
        self.assertEqual(set(re.findall(r'=> "(RosterConstruction\w+)"',source)),expected)
        self.assertEqual({x for x in output.BOUNDARIES if x.startswith('RosterConstruction')},expected)
        for label in expected:
            for kind in ['Begin','Complete','SignerUncertain','AuthorityExpired','AuthorityConflict']:
                self.assertTrue(output.safe_failure(self.failure(label+':'+kind)))
        for value in ['RosterConstructionUnknown:Begin','RosterConstructionReserve:AuthorityUnknown',
                      'RosterConstructionConsume:AuthorityExpired private-data',
                      'RosterConstructionSend:SignerUncertain:private-data']:
            self.assertFalse(output.safe_failure(self.failure(value)))

    def test_completion_diagnostics_preserve_exact_closed_layers(self):
        expected=set("CompletionObservationDenied CompletionPostReentryCurrent CompletionReadBinding CompletionConstructionTime CompletionCallerBinding CompletionConstructionRequest CompletionOriginal CompletionPairApproval CompletionPairBegin CompletionPairFinish CompletionReentryRequest CompletionRequestApproval CompletionReentryBegin CompletionReentryFinish CompletionConstructionBegin CompletionConstructionFinish".split())
        source=(ROOT/'crates/wholepact-native-host/src/host/synthetic_roster_trace_v1.rs').read_text()
        body=re.search(r'labels! \{ Phase \{(.*?)\} \}',source,re.S).group(1)
        actual={x.strip() for x in body.split(',') if x.strip().startswith('Completion')}
        self.assertEqual(actual,expected)
        self.assertEqual({x for x in output.BOUNDARIES if x.startswith('Completion')},expected)
        bridge=set("BridgeBinding BridgeConflict BridgeMissing BridgeUncertain BridgeLimit BridgePermission BridgeRecoveryRequired BridgeCompleteOriginRecoveryUnavailable BridgeVerification BridgeSignerOriginUnavailable BridgeJournal BridgeAuthority BridgeWallet BridgeIpc".split())
        self.assertEqual({x for x in output.OUTCOMES if x.startswith('Bridge')},bridge)
        for phase in expected:
            for kind in bridge|{x for x in output.OUTCOMES if x.startswith('Origin')}:
                self.assertTrue(output.safe_failure(self.failure(phase+':'+kind)))
        for value in ['CompletionUnknown:BridgePermission', 'CompletionPairBegin:OriginUnknown',
                      'CompletionReentryBegin:BridgeUnknown', 'CompletionPairFinish:OriginIoOther private',
                      'CompletionConstructionFinish:OriginPermission:private']:
            self.assertFalse(output.safe_failure(self.failure(value)))

    def test_exact_observation_projection_is_exhaustive_and_payload_free(self):
        variants=set("Permission Lineage Binding Storage RecoveryRequired StateChanged ProfileChanged Budget Roster".split())
        expected={'Exact'+variant for variant in variants}
        source=(ROOT/'crates/wholepact-native-host/src/host/synthetic_roster_trace_v1.rs').read_text()
        body=source.split('fn observation_error(',1)[1].split('pub(super) fn import',1)[0]
        self.assertEqual(set(re.findall(r'E::(\w+) => Outcome::Exact\w+',body)),variants)
        self.assertIn('E::Sync(error) => sync_error(error)',body)
        self.assertNotIn('=> format!',body)
        self.assertEqual({label for label in output.OUTCOMES if label.startswith('Exact')},expected)
        for outcome in expected|{'SyncInterrupted','ChainClockUnavailable','ChainBackendFailure'}:
            self.assertTrue(output.safe_failure(self.failure('CompletionObservationDenied:'+outcome)))
        for value in ['CompletionObservationDenied:ExactUnknown',
                      'CompletionObservationDenied:ExactPermission private',
                      'CompletionObservationDenied:ChainBackendFailure:12345',
                      'CompletionObservationDeniedUnknown:ExactLineage']:
            self.assertFalse(output.safe_failure(self.failure(value)))
        existing=source.split('fn lower_error_projection_preserves_only_closed_kinds()',1)[1].split('#[test]',1)[0]
        for variant in variants:
            self.assertIn('(Exact::'+variant+', "Exact'+variant+'")',existing)
        self.assertEqual(output.LOWER_ERROR_TESTS,('host::synthetic_roster_trace_v1::lower_error_projection_preserves_only_closed_kinds',))

    def test_native_observation_clock_denials_preserve_exact_static_kinds(self):
        expected=set("ObservationClockRollback ObservationClockWallExpired ObservationClockMonotonicExpired ObservationRetainedClockRead ObservationRetainedClockDenied ObservationAdmittedClockRead ObservationAdmittedClockDenied".split())
        source=(ROOT/'crates/wholepact-signer-origin/src/manual_roster_candidate_selection_v2_client.rs').read_text()
        body=source.split('pub(super) fn completion_clock_denied(',1)[1].split('pub(super) fn observe_completion_wall(',1)[0]
        self.assertEqual(set(re.findall(r'=> "(Observation\w+)"',body)),expected)
        self.assertEqual({label for label in output.BOUNDARIES if label.startswith('Observation')},expected)
        self.assertNotIn('now_ms(',body)
        self.assertNotIn('Instant::now(',body)
        self.assertIn('[JOINED_DIAGNOSTIC {label} Begin]',body)
        for label in expected:
            self.assertTrue(output.safe_failure(self.failure(label+':Begin')))
        for value in ['ObservationClockUnknown:Begin','ObservationAdmittedClockDenied:Unknown',
                      'ObservationClockWallExpired:Begin private',
                      'ObservationClockMonotonicExpired:Begin:12345']:
            self.assertFalse(output.safe_failure(self.failure(value)))
        check=source.split('pub(super) fn require_completion_at(',1)[1].split('// Denial-only opt-in qualification output.',1)[0]
        self.assertEqual(check.count('observe_completion_wall(maximum, wall)'),1)
        self.assertEqual(check.count('completion_budget(wall, expires, wall)'),1)
        self.assertEqual(check.count('monotonic >= deadline'),1)
        self.assertLess(check.index('observe_completion_wall(maximum, wall)'),check.index('completion_budget(wall, expires, wall)'))
        self.assertLess(check.index('completion_budget(wall, expires, wall)'),check.index('monotonic >= deadline'))

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

    def test_read_wave_preflight_keeps_original_inputs_and_effect_tail(self):
        names=('actual_read_wave_prepares_every_item_before_original_order_execution',
               'failed_read_wave_drops_prepared_values_without_execution_or_retry')
        expected=tuple(output.PREFIX+'observed_joined_v3::'+name for name in names)
        self.assertEqual(output.READ_WAVE_TESTS,expected)
        path=ROOT/'crates/wholepact-native-host/src/host/manual_enrollment/command/roster_publication_v2/sequential_construction_v3_qualification/observed_joined_v3.rs'
        source=path.read_text()
        timed_loop=('for (ordinal, (entry, owner, prepared)) in read_wave.into_iter().enumerate() {\n'
                    '        crate::host::synthetic_roster_timing_v1::select(ordinal);')
        self.assertEqual(source.count(timed_loop),1)
        source=source.replace(timed_loop,'for (entry, owner, prepared) in read_wave {',1)
        self.assertEqual(hashlib.sha256(source.encode()).hexdigest(),'269ce7d617fefac3115b6be58e9dfcef2f92deb2068a6039384429bdefde6fa2')
        for name in names:
            self.assertEqual(source.count('fn '+name+'()'),1)
        function=source.split('fn observe_two_inner<',1)[1].split('// A private collect barrier',1)[0]
        self.assertEqual(function.count('prepared_common_context_read_v3::prepare('),1)
        self.assertEqual(function.count('prepared.begin_pair('),1)
        self.assertLess(function.index('let read_wave = prepare_read_wave('),function.index('prepared_common_context_read_v3::prepare('))
        self.assertLess(function.index('prepared_common_context_read_v3::prepare('),function.index('for (entry, owner, prepared) in read_wave'))
        self.assertLess(function.index('for (entry, owner, prepared) in read_wave'),function.index('prepared.begin_pair('))
        execution=function.split('for (entry, owner, prepared) in read_wave',1)[1]
        self.assertLess(execution.index('check_scenario(original_scenario_deadline)?;'),execution.index('let witness = witnesses.for_original(owner)?;'))
        self.assertLess(execution.index('coordinator.check_current(host)?;'),execution.index('let witness = witnesses.for_original(owner)?;'))
        self.assertLess(execution.index('let witness = witnesses.for_original(owner)?;'),execution.index('witness\n                .serve_original_roster_attempt_v2('))
        inputs=source.split('pub(super) fn inputs()',1)[1].split('#[test]',1)[0]
        self.assertEqual(hashlib.sha256(inputs.encode()).hexdigest(),'4b1cc2f8f7e0cd5aa77fecfb3e46423a67a1cee07b0592fbc7b64bcf599e5d3a')
        tail=source.split('let (actual, read_operation, handoff_operation) = prepared.exact_read_parts();',1)[1].split('    check_scenario(original_scenario_deadline)?;\n    let roster',1)[0]
        self.assertEqual(hashlib.sha256(tail.encode()).hexdigest(),'dd33079c1cacfe52a211c349fc473d1873c9a6f80096e0546656ffc6e304f125')
        combined=output.PURE_TESTS+output.POLICY_ENVELOPE_TESTS+output.PROMPT_RENDERING_TESTS+output.LOWER_ERROR_TESTS+output.DENIAL_TESTS+output.ROLLING_TRANSCRIPT_TESTS+output.AUTHORITY_PROJECTION_TESTS+output.READ_WAVE_TESTS
        self.assertEqual(len(combined),38)
        self.assertEqual(len(set(combined)),38)
        self.assertTrue(set(expected).isdisjoint(row[0] for row in output.TESTS.values()))

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
            self.assertIn(name,output.SIGNER_VALIDATION_TESTS+output.SIGNER_BOOKKEEPING_TESTS+output.SIGNER_PRECONSTRUCTION_TESTS+output.SIGNER_BIRTH_LINK_TESTS+output.SIGNER_ENDPOINT_CHANNEL_TESTS+output.SIGNER_SNAPSHOT_STORAGE_TESTS+output.SIGNER_SHAPE_TAMPER_TESTS+output.SIGNER_REENTRY_COMPATIBILITY_TESTS+output.SIGNER_CALL_LOCAL_TESTS+output.SIGNER_AUDIT_STORAGE_TESTS+output.SIGNER_AUDIT_COMPATIBILITY_TESTS+output.SIGNER_NAMED_ORIGIN_SNAPSHOT_TESTS+output.SIGNER_LINEAGE_PREDICATE_TESTS+output.SIGNER_TIMING_TESTS+output.SIGNER_DURABLE_LABEL_TESTS+output.SIGNER_DURABLE_RECEIPT_TESTS)
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
        self.assertEqual([argv[2] for argv,_ in calls], [name for name in output.SIGNER_VALIDATION_TESTS+output.SIGNER_BOOKKEEPING_TESTS+output.SIGNER_PRECONSTRUCTION_TESTS+output.SIGNER_BIRTH_LINK_TESTS+output.SIGNER_ENDPOINT_CHANNEL_TESTS+output.SIGNER_SNAPSHOT_STORAGE_TESTS+output.SIGNER_SHAPE_TAMPER_TESTS+output.SIGNER_REENTRY_COMPATIBILITY_TESTS+output.SIGNER_CALL_LOCAL_TESTS+output.SIGNER_AUDIT_STORAGE_TESTS+output.SIGNER_AUDIT_COMPATIBILITY_TESTS+output.SIGNER_NAMED_ORIGIN_SNAPSHOT_TESTS+output.SIGNER_LINEAGE_PREDICATE_TESTS+output.SIGNER_TIMING_TESTS+output.SIGNER_DURABLE_LABEL_TESTS+output.SIGNER_DURABLE_RECEIPT_TESTS for _ in range(2)])
        self.assertEqual(captured.getvalue(),'CI_SYNTHETIC_SIGNER_VALIDATION passed=41 crypto_file_cases=4 bookkeeping_cases=2 replay_cases=6 endpoint_channel_cases=4 snapshot_storage_cases=2 shape_tamper_cases=1 compatibility_cases=3 call_local_cases=2 audit_storage_cases=1 audit_compatibility_cases=2 named_origin_snapshot_cases=3 lineage_predicate_cases=2 timing_counter_cases=3 label_grammar_cases=1 current_receipt_cases=5 native_payment_verified=false raw_output_discarded=true\n')

    def test_checkpoint_engine_projection_is_exact_closed_public_kinds(self):
        labels=set(('EngineCheckpointClaim', 'EngineCheckpointPlan', 'EngineCheckpointRetained', 'EngineCheckpointParts', 'EngineCheckpointNative', 'EngineCheckpointHeld', 'EngineCheckpointRestriction', 'EngineCheckpointConstruct', 'EngineCheckpointInspect', 'EngineCheckpointActionLimit', 'EngineCheckpointConsent', 'EngineCheckpointReceipt', 'EngineCheckpointRecord', 'EngineCheckpointEnqueue', 'EngineCheckpointFinish', 'EngineCheckpointContext'))
        outcomes=set(('BridgeAuthority', 'BridgeBinding', 'BridgeCompleteOriginRecoveryUnavailable', 'BridgeConflict', 'BridgeIpc', 'BridgeJournal', 'BridgeLimit', 'BridgeMissing', 'BridgePermission', 'BridgeRecoveryRequired', 'BridgeSignerOriginUnavailable', 'BridgeUncertain', 'BridgeVerification', 'BridgeWallet', 'EngineAccessDenied', 'EngineCandidateVerificationFailed', 'EngineIdempotencyConflict', 'EngineInvalidRequest', 'EngineInvalidTransition', 'EngineLiveAuthorizationExists', 'EngineManualConstructionDenied', 'EngineNotFound', 'EngineRecoveryRequired', 'EngineResourceExhausted', 'EngineRetainedObservationUnavailable', 'EngineRevisionConflict', 'EngineStorageProtectionRequired', 'EngineStorageUnavailable', 'EngineUnclassified', 'JobConsentDenied', 'JobIdempotencyConflict', 'JobInvalidRequest', 'JobNotFound', 'JobRecoveryRequired', 'JobResourceExhausted', 'JobStateConflict', 'JobStorage', 'JobUnsupportedSchema', 'JobVerificationFailed', 'ProtocolActionMapping', 'ProtocolBuilderInput', 'ProtocolBuilderOutput', 'ProtocolContext', 'ProtocolContribution', 'ProtocolDisclosure', 'ProtocolFee', 'ProtocolFinalize', 'ProtocolInput', 'ProtocolManifest', 'ProtocolOutput', 'ProtocolPczt', 'ProtocolUnclassified', 'StoreAlreadyExists', 'StoreBudgetExceeded', 'StoreDatabase', 'StoreEncoding', 'StoreFile', 'StoreIdempotencyConflict', 'StoreInputReserved', 'StoreInvalidInput', 'StoreInvalidTransition', 'StoreLiveAuthorizationExists', 'StoreNotFound', 'StorePoisoned', 'StoreRecoveryRequired', 'StoreResourceExhausted', 'StoreRevisionConflict', 'StoreStorageSecurity', 'StoreUnsupportedSchema', 'StoreWriterEpochMismatch'))
        self.assertEqual({label for label in output.BOUNDARIES if label.startswith('EngineCheckpoint')},labels)
        source=(ROOT/'crates/wholepact-engine/src/manual_roster_construct_v3/synthetic_diagnostics.rs').read_text()
        actual_labels=set(re.findall(r'=> "(EngineCheckpoint\w+)"',source))
        actual_outcomes=set(re.findall(r'"((?:Bridge|Engine|Job|Protocol|Store)[A-Z]\w+)"',source))-actual_labels
        self.assertEqual(actual_labels,labels)
        self.assertEqual(actual_outcomes,outcomes)
        self.assertEqual(len(labels),16)
        self.assertEqual(len(outcomes),70)
        self.assertTrue(outcomes <= output.OUTCOMES)
        for label in labels:
            for outcome in outcomes | {'Begin','Complete'}:
                self.assertTrue(output.safe_failure(self.failure(label+':'+outcome)))
                self.assertFalse(output.safe_failure(self.failure(label+':'+outcome+' private payload')))
            self.assertFalse(output.safe_failure(self.failure(label+'Unknown:EngineUnclassified')))
        self.assertFalse(output.safe_failure(self.failure('EngineCheckpointConstruct:ProtocolPrivate')))
        self.assertFalse(output.safe_failure(self.failure('EngineCheckpointClaim:ENGINE_ERROR_CODE')))
        self.assertIn('_ => "EngineUnclassified"',source)
        self.assertIn('_ => "ProtocolUnclassified"',source)
        self.assertNotIn('error.to_string()',source)
        self.assertNotIn('format!',source)
        parent=(ROOT/'crates/wholepact-engine/src/manual_roster_construct_v3.rs').read_text()
        self.assertIn('#[cfg(feature = "synthetic-qualification")]\nmod synthetic_diagnostics;',parent)
        self.assertEqual(parent.count('let result = $operation;'),1)
        self.assertEqual(parent.count('let permitted = $predicate;'),1)

    def test_checkpoint_host_precoarsening_is_closed_and_result_preserving(self):
        labels={'CheckpointEngine','CheckpointWalletUnwind','CheckpointFinish',
                'CheckpointObservations','CheckpointOutput','CheckpointBeforeClaim',
                'CheckpointClaimMayExist'}
        self.assertEqual({label for label in output.BOUNDARIES if label.startswith('Checkpoint')},labels)
        for label in labels:
            for outcome in ('Begin','Complete','HostPermission','HostReceipt','HostAuthentication'):
                value=label+':'+outcome
                self.assertTrue(output.safe_failure(self.failure(value)))
                self.assertFalse(output.safe_failure(self.failure(value+' private receipt')))
            self.assertFalse(output.safe_failure(self.failure(label+'Unknown:HostReceipt')))
        source=(ROOT/'crates/wholepact-native-host/src/host/financial/'
                'manual_roster_candidate_assembly_v3.rs').read_text()
        body=source.split('pub(in crate::host) fn construct_observed_checkpoint(',1)[1].split('fn exact_claim_uncertain_error',1)[0]
        for operation in ('with_common_context_roster(slots, &excluded,',
                          'host.engine.checkpoint_manual_roster_from_retained_v3(',
                          'pending.finish()', 'restriction.check_observations()',
                          'host.terminal.json(&result)', '.classify_outer_result(result)',
                          'progress.claim_digest().as_deref()'):
            self.assertEqual(body.count(operation),1)
        self.assertLess(body.index('checkpoint_manual_roster_from_retained_v3('),body.index('pending.finish()'))
        self.assertLess(body.index('pending.finish()'),body.index('restriction.check_observations()'))
        self.assertLess(body.index('restriction.check_observations()'),body.index('host.terminal.json(&result)'))
        classified=body.split('.classify_outer_result(result)',1)[1]
        self.assertLess(classified.index('match &error'),classified.index('match error'))
        self.assertIn('ManualRosterConstructionOuterErrorV3::BeforeClaim(error) => error,',classified)
        self.assertIn('ManualRosterConstructionOuterErrorV3::ClaimMayExist(_) => {',classified)

    def test_postconsume_poll_and_owner_labels_are_closed(self):
        labels=('SignerPollCancelled','SignerPollDeadline','SignerPollTerminal',
                'RosterConstructionIntoNamed','RosterConstructionNamedOwner',
                'RosterConstructionFinalOwner')
        for label in labels:
            self.assertIn(label,output.BOUNDARIES)
            valid=('[JOINED_FAILURE exit=Some(101) signal=None core_dumped=false '
                   'inputs=162/204 reason=ChildExit static_boundaries='+label+':SignerLocked]')
            self.assertTrue(output.safe_failure(valid))
            self.assertFalse(output.safe_failure(valid.replace(label,label+'Unknown')))
            self.assertFalse(output.safe_failure(valid.replace(':SignerLocked]',':SignerLocked private]')))
        worker=(ROOT/'crates/wholepact-native-host/src/host/manual_enrollment/command/'
                'roster_publication_v2/sequential_construction_v3_qualification/'
                'joined_signer_worker_v1.rs').read_text()
        poll=worker.split('fn poll_until(',1)[1].split('\nfn execute(',1)[0]
        self.assertEqual(poll.count('cancelled.load(Ordering::Acquire)'),1)
        self.assertEqual(poll.count('Instant::now()'),1)
        self.assertEqual(poll.count('poll()'),1)
        self.assertLess(poll.index('cancelled.load'),poll.index('Instant::now()'))
        self.assertLess(poll.index('Instant::now()'),poll.index('let result = poll();'))
        self.assertIn('if result.map_err(|error| signer_error(error, stage))?',poll)
        self.assertIn('thread::sleep(Duration::from_millis(2));',poll)

    def test_lineage_predicate_preflight_keeps_original_validation_position(self):
        prefix='native_ui::born_manual_roster_v2::common_context_reentry::lineage_comparison_tests::'
        expected=tuple(prefix+name for name in (
            'exact_lineage_comparison_refuses_another_well_formed_digest',
            'same_call_lineage_probe_preserves_both_sentinel_originals',
        ))
        self.assertEqual(output.SIGNER_LINEAGE_PREDICATE_TESTS,expected)
        base=ROOT/'crates/wholepact-signer/src/native_ui'
        source=(base/'born_manual_roster_v2/common_context_reentry.rs').read_text()
        self.assertIn('mod common_context_reentry;', (base/'born_manual_roster_v2/mod.rs').read_text())
        self.assertIn('mod lineage_comparison_tests {',source)
        for name in expected:
            self.assertEqual(len(re.findall(r'#\[test\]\s+fn '+name.rsplit('::',1)[1]+r'\(',source)),1)
        exact=source.split('    fn require_exact_request(',1)[1].split('    pub(super) fn prepare(',1)[0]
        self.assertEqual(exact.count('request.validate()'),1)
        self.assertEqual(exact.count('self.lineage.digest()'),1)
        self.assertLess(exact.index('request.validate()'),exact.index('peer.grant_id != self.peer.grant_id'))
        self.assertLess(exact.index('peer.grant_id != self.peer.grant_id'),exact.index('self.lineage.digest()'))
        self.assertLess(exact.index('self.lineage.digest()'),exact.index('request.plan != self.lineage.request.original_read.plan'))
        self.assertIn('request.requested_at_ms < self.lineage.admitted_at_ms',exact)
        self.assertIn('request.admission_expires_at_ms > self.lineage.completion_expires_at_ms',exact)
        self.assertNotIn('qualification_check_wrong_lineage',source)
        fixture=(base/'qualification/born_roster_construction_v3.rs').read_text()
        self.assertNotIn('qualification_check_wrong_lineage',fixture)
        self.assertIn('approve_exact_consumption_without_old_owner_drain(ui, self.epoch)?;',fixture)

    def test_named_origin_snapshot_preflight_is_three_exact_encrypted_cases(self):
        prefix='consent_journal::common_context_reentry_audit_tests::'
        expected=tuple(prefix+name for name in (
            'named_origin_snapshot_matches_complete_reader_and_preserves_outer_transactions',
            'named_origin_snapshot_rechecks_identity_evidence_schema_and_local_rows',
            'named_origin_snapshot_revalidates_changed_consumed_rows_on_every_call',
        ))
        self.assertEqual(output.SIGNER_NAMED_ORIGIN_SNAPSHOT_TESTS,expected)
        base=ROOT/'crates/wholepact-signer/src/consent_journal'
        self.assertIn('mod common_context_reentry_audit_tests;', (base/'mod.rs').read_text())
        source=(base/'common_context_reentry_audit_tests.rs').read_text()
        for name in expected:
            self.assertEqual(len(re.findall(r'#\[test\]\s+fn '+name.rsplit('::',1)[1]+r'\(',source)),1)
        previous=(output.SIGNER_VALIDATION_TESTS+output.SIGNER_BOOKKEEPING_TESTS
                  +output.SIGNER_PRECONSTRUCTION_TESTS+output.SIGNER_BIRTH_LINK_TESTS
                  +output.SIGNER_ENDPOINT_CHANNEL_TESTS+output.SIGNER_SNAPSHOT_STORAGE_TESTS
                  +output.SIGNER_SHAPE_TAMPER_TESTS+output.SIGNER_REENTRY_COMPATIBILITY_TESTS
                  +output.SIGNER_CALL_LOCAL_TESTS+output.SIGNER_AUDIT_STORAGE_TESTS
                  +output.SIGNER_AUDIT_COMPATIBILITY_TESTS)
        self.assertEqual(len(previous),27)
        self.assertEqual(len(set(previous+expected)),30)
        self.assertTrue(set(expected).isdisjoint(previous))

    def test_call_local_audit_preflight_is_five_exact_distinct_cases(self):
        prefix='consent_journal::common_context_reentry_audit_tests::'
        local=tuple(prefix+name for name in (
            'call_local_invocation_binding_keeps_every_phase_admission_digest',
            'call_local_invocation_binding_never_survives_signature_read_or_history_changes',
        ))
        storage=(prefix+'stored_audit_digests_and_shapes_are_revalidated_on_every_read',)
        compatibility=tuple(prefix+name for name in (
            'signed_handoff_each_missing_local_suffix_stays_charged_and_orphans_fail',
            'signed_handoff_exact_lineage_substitutions_fail_after_complete_validation',
        ))
        self.assertEqual(output.SIGNER_CALL_LOCAL_TESTS,local)
        self.assertEqual(output.SIGNER_AUDIT_STORAGE_TESTS,storage)
        self.assertEqual(output.SIGNER_AUDIT_COMPATIBILITY_TESTS,compatibility)
        base=ROOT/'crates/wholepact-signer/src/consent_journal'
        self.assertIn('mod common_context_reentry_audit_tests;', (base/'mod.rs').read_text())
        source=(base/'common_context_reentry_audit_tests.rs').read_text()
        for name in local+storage+compatibility:
            self.assertEqual(len(re.findall(r'#\[test\]\s+fn '+name.rsplit('::',1)[1]+r'\(',source)),1)
        previous=(output.SIGNER_VALIDATION_TESTS+output.SIGNER_BOOKKEEPING_TESTS
                  +output.SIGNER_PRECONSTRUCTION_TESTS+output.SIGNER_BIRTH_LINK_TESTS
                  +output.SIGNER_ENDPOINT_CHANNEL_TESTS+output.SIGNER_SNAPSHOT_STORAGE_TESTS
                  +output.SIGNER_SHAPE_TAMPER_TESTS+output.SIGNER_REENTRY_COMPATIBILITY_TESTS)
        self.assertEqual(len(previous),22)
        all_cases=previous+local+storage+compatibility
        self.assertEqual(len(all_cases),27)
        self.assertEqual(len(set(all_cases)),27)

    def test_reentry_snapshot_preflight_is_six_exact_distinct_cases(self):
        prefix='consent_journal::common_context_reentry_audit_tests::'
        storage=tuple(prefix+name for name in (
            'owner_snapshot_is_fresh_and_never_commits_a_callers_transaction',
            'owner_snapshot_revalidates_changed_payload_and_missing_rows',
        ))
        shape=(prefix+'completed_shape_pass_still_rejects_lineage_history_and_reservation_tampering',)
        compatibility=tuple(prefix+name for name in (
            'signed_handoff_reopen_requires_exact_authorized_only_original_journal',
            'signed_handoff_encrypted_six_phase_reopen_is_exact_and_atomic',
            'explicit_v5_keeps_old_bytes_charge_and_never_issues_recovery',
        ))
        self.assertEqual(output.SIGNER_SNAPSHOT_STORAGE_TESTS,storage)
        self.assertEqual(output.SIGNER_SHAPE_TAMPER_TESTS,shape)
        self.assertEqual(output.SIGNER_REENTRY_COMPATIBILITY_TESTS,compatibility)
        base=ROOT/'crates/wholepact-signer/src/consent_journal'
        self.assertIn('mod common_context_reentry_audit_tests;', (base/'mod.rs').read_text())
        source=(base/'common_context_reentry_audit_tests.rs').read_text()
        for name in storage+shape+compatibility:
            self.assertEqual(len(re.findall(r'#\[test\]\s+fn '+name.rsplit('::',1)[1]+r'\(',source)),1)
        all_cases=(output.SIGNER_VALIDATION_TESTS+output.SIGNER_BOOKKEEPING_TESTS
                   +output.SIGNER_PRECONSTRUCTION_TESTS+output.SIGNER_BIRTH_LINK_TESTS
                   +output.SIGNER_ENDPOINT_CHANNEL_TESTS+storage+shape+compatibility)
        self.assertEqual(len(all_cases),22)
        self.assertEqual(len(set(all_cases)),22)

    def test_endpoint_channel_preflight_is_four_exact_private_cases(self):
        prefix='native_ui::synthetic_born_joined_qualification::construction_fixture::endpoint_report_tests::'
        expected=tuple(prefix+name for name in (
            'original_report_requires_transfer_and_is_received_once',
            'missing_or_dropped_report_is_terminal',
            'separate_original_report_channels_cannot_supply_each_other',
            'invalid_report_consumes_the_only_publication_opportunity',
        ))
        self.assertEqual(output.SIGNER_ENDPOINT_CHANNEL_TESTS,expected)
        base=ROOT/'crates/wholepact-signer/src/native_ui'
        self.assertIn('#[path = "qualification/born_joined_fixture_v1.rs"]', (base/'mod.rs').read_text())
        self.assertIn('pub mod synthetic_born_joined_qualification;', (base/'mod.rs').read_text())
        fixture=(base/'qualification/born_joined_fixture_v1.rs').read_text()
        self.assertIn('#[path = "born_joined_construction_v3.rs"]',fixture)
        self.assertIn('mod construction_fixture;',fixture)
        parent=(base/'qualification/born_joined_construction_v3.rs').read_text()
        self.assertIn('#[path = "born_joined_construction_v3/endpoint_report_tests.rs"]',parent)
        self.assertIn('mod endpoint_report_tests;',parent)
        source=(base/'qualification/born_joined_construction_v3/endpoint_report_tests.rs').read_text()
        for name in expected:
            self.assertEqual(len(re.findall(r'#\[test\]\s+fn '+name.rsplit('::',1)[1]+r'\(',source)),1)
        combined=output.SIGNER_VALIDATION_TESTS+output.SIGNER_BOOKKEEPING_TESTS+output.SIGNER_PRECONSTRUCTION_TESTS+output.SIGNER_BIRTH_LINK_TESTS+expected
        self.assertEqual(len(combined),16)
        self.assertEqual(len(set(combined)),16)

    def test_signer_preconstruction_is_three_exact_authenticated_history_cases(self):
        prefix='account::birth::enrollment::roster_v2::continuation::preconstruction::tests::'
        expected=tuple(prefix+name for name in (
            'approval_history_keeps_original_attempt_and_legacy_refusal',
            'exposure_and_tampered_approval_history_remain_refused',
            'approval_cannot_cross_enrollment_or_original_attempt',
        ))
        self.assertEqual(output.SIGNER_PRECONSTRUCTION_TESTS,expected)
        base=ROOT/'crates/wholepact-signer/src/account/birth/enrollment/roster_v2'
        self.assertIn('mod preconstruction;', (base/'continuation.rs').read_text())
        source=(base/'continuation/preconstruction.rs').read_text()
        self.assertIn('mod tests {',source)
        self.assertIn('recorded_fixture_history(',source)
        fixture=re.search(r'include_str!\(\s*"([^"]+)"',source).group(1)
        self.assertTrue((base/'continuation'/fixture).resolve().is_file())
        for name in expected:
            self.assertEqual(len(re.findall(r'#\[test\]\s+fn '+name.rsplit('::',1)[1]+r'\(',source)),1)
        self.assertEqual(len(set(output.SIGNER_VALIDATION_TESTS+output.SIGNER_BOOKKEEPING_TESTS+expected)),9)

    def test_birth_link_preflight_is_three_exact_complete_history_audits(self):
        prefix='account::birth::history::preconstruction_tests::'
        expected=tuple(prefix+name for name in (
            'original_birth_link_accepts_approval_only_and_preserves_legacy_refusal',
            'original_birth_link_rejects_foreign_extension_and_other_original',
            'original_birth_link_rejects_reserved_consumed_and_tampered_history',
        ))
        self.assertEqual(output.SIGNER_BIRTH_LINK_TESTS,expected)
        base=ROOT/'crates/wholepact-signer/src/account/birth'
        parent=(base/'history.rs').read_text()
        self.assertIn('#[path = "history/preconstruction_tests.rs"]',parent)
        self.assertIn('mod preconstruction_tests;',parent)
        source=(base/'history/preconstruction_tests.rs').read_text()
        self.assertIn('recorded_fixture_history(',source)
        fixture=re.search(r'include_str!\(\s*"([^"]+)"',source).group(1)
        self.assertTrue((base/'history'/fixture).resolve().is_file())
        for name in expected:
            self.assertEqual(len(re.findall(r'#\[test\]\s+fn '+name.rsplit('::',1)[1]+r'\(',source)),1)
        self.assertEqual(len(set(output.SIGNER_VALIDATION_TESTS+output.SIGNER_BOOKKEEPING_TESTS+output.SIGNER_PRECONSTRUCTION_TESTS+expected)),12)

    def test_continuation_birth_audit_diagnostics_are_exact_denial_only_labels(self):
        expected=set('RosterBirthHistoryGate RosterBirthExtension RosterBirthOriginal RosterBirthLinkage ContinuationRetainedSource ContinuationAttemptedSource ContinuationWriterSource ContinuationHistoryReplay ContinuationPairing ContinuationPreparedReview ContinuationSource ContinuationBirthLink ContinuationPreconstruction ContinuationHistoryGate ContinuationHistoryArchive ContinuationRetainedReceipt ContinuationPreviousLoad ContinuationProposalCapacity ContinuationProposalIndex ContinuationAttemptSequence ContinuationProposalValidation'.split())
        source=(ROOT/'crates/wholepact-signer/src/account/birth/enrollment/roster_v2/continuation/diagnostics.rs').read_text()
        actual=set(re.findall(r'=> "((?:RosterBirth|Continuation)\w+)"',source))
        self.assertEqual(actual,expected)
        self.assertEqual({name for name in output.BOUNDARIES if name.startswith(('RosterBirth','Continuation'))},expected)
        self.assertEqual(len(expected),21)
        outcomes=set(re.findall(r'=> "((?:Signer|Authority)\w+)"',source))
        self.assertTrue(outcomes <= output.OUTCOMES)
        for name in expected:
            for outcome in outcomes:
                self.assertTrue(output.safe_failure(self.failure(name+':'+outcome)))
        for value in ['ContinuationUnknown:SignerUnavailable','RosterBirthUnknown:AuthorityConflict',
                      'ContinuationSource:SignerUnavailable private-data','RosterBirthLinkage:AuthorityInvalidBinding:private-data']:
            self.assertFalse(output.safe_failure(self.failure(value)))
        self.assertFalse(output.safe_failure(self.failure('ContinuationBirthLink:SignerUnavailable')+' private-data'))

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

    def test_authority_renderer_preflight_is_six_exact_private_cases(self):
        prefix='native_witness_owner::window::ephemeral_fixture_v1::public_control_navigation_v1::tests::'
        names=(
            'wheel_navigation_reaches_actual_disabled_controls_without_mutating_form',
            'missing_exact_control_stops_after_finite_wheel_events',
            'exact_label_requires_visible_clip_and_viewport',
            'retained_receipt_scroll_is_independent_of_actual_selection_navigation',
            'same_parent_scroll_areas_use_distinct_stable_production_ids',
            'qualified_area_requires_sizing_then_actual_focused_primary_click',
        )
        self.assertEqual(output.AUTHORITY_RENDERER_TESTS,tuple(prefix+name for name in names))
        base=ROOT/'crates/wholepact-authority/src/native_witness_owner/window'
        parent=(base/'ephemeral_fixture_v1.rs').read_text()
        source=(base/'ephemeral_fixture_v1/public_control_navigation_v1.rs').read_text()
        self.assertIn('mod public_control_navigation_v1;',parent)
        self.assertIn('mod tests {',source)
        for name in names:
            self.assertEqual(len(re.findall(r'#\[test\]\s+fn '+name+r'\(',source)),1)
        self.assertEqual(len(set(output.AUTHORITY_RENDERER_TESTS)),6)
        self.assertTrue(set(output.AUTHORITY_RENDERER_TESTS).isdisjoint(output.SIGNER_VALIDATION_TESTS+output.SIGNER_BOOKKEEPING_TESTS))
        shell=(ROOT/'scripts/ci-synthetic-linux.sh').read_text()
        build='timeout --signal=TERM --kill-after=30s 1200s rustup run 1.99.0 cargo test --locked --release -p wholepact-authority --all-features --lib --no-run --message-format=json'
        selected='python3 -B scripts/ci-synthetic-output.py "$authority_executable" authority-rendering'
        self.assertEqual(shell.count(build),1)
        self.assertEqual(shell.count(selected),1)
        self.assertIn("get('name')=='wholepact_authority'",shell)
        self.assertLess(shell.index(build),shell.index(selected))
        self.assertLess(shell.index(selected),shell.index('"$executable" initial'))

    def test_authority_renderer_runs_exact_bounded_cases_and_withholds_output(self):
        calls=[]
        def fake_run(argv, **kwargs):
            calls.append((argv,kwargs))
            name=argv[2]
            self.assertIn(name,output.AUTHORITY_RENDERER_TESTS)
            self.assertEqual(argv[:2],['/verified/authority','--exact'])
            self.assertEqual(argv[3],'--test-threads=1')
            if argv[-1]=='--list':
                self.assertEqual(len(argv),5)
                self.assertEqual(kwargs,dict(capture_output=True,timeout=30,check=True))
                return output.subprocess.CompletedProcess(argv,0,(name+': test\n\n1 test, 0 benchmarks\n').encode(),b'')
            self.assertEqual(len(argv),4)
            self.assertEqual(kwargs,dict(stdout=output.subprocess.PIPE,stderr=output.subprocess.STDOUT,timeout=30))
            return output.subprocess.CompletedProcess(argv,0,b'private inert output')
        captured=io.StringIO()
        with mock.patch.object(output.resource,'getrlimit',return_value=(0,0)), \
             mock.patch.object(output.subprocess,'run',side_effect=fake_run), \
             contextlib.redirect_stdout(captured):
            output.run_authority_rendering('/verified/authority')
        self.assertEqual([argv[2] for argv,_ in calls],[name for name in output.AUTHORITY_RENDERER_TESTS for _ in range(2)])
        self.assertEqual(captured.getvalue(),'CI_SYNTHETIC_AUTHORITY_RENDERER passed=6 native_payment_verified=false attended_gui_verified=false raw_output_discarded=true\n')

    def test_authority_renderer_missing_failed_or_timed_out_refuses(self):
        name=output.AUTHORITY_RENDERER_TESTS[0]
        listed=output.subprocess.CompletedProcess([],0,(name+': test\n\n1 test, 0 benchmarks\n').encode(),b'')
        cases=[
            [output.subprocess.CompletedProcess([],0,b'0 tests, 0 benchmarks\n',b'')],
            [output.subprocess.CompletedProcess([],0,listed.stdout,b'private error')],
            [listed,output.subprocess.CompletedProcess([],101,b'private panic')],
            [listed,output.subprocess.CompletedProcess([],0,b'x'*(1024*1024+1))],
            [listed,output.subprocess.TimeoutExpired('private command',30,output=b'private output')],
        ]
        for results in cases:
            captured=io.StringIO()
            with mock.patch.object(output.resource,'getrlimit',return_value=(0,0)), \
                 mock.patch.object(output.subprocess,'run',side_effect=results) as run, \
                 contextlib.redirect_stdout(captured):
                with self.assertRaises(Exception): output.run_authority_rendering('/verified/authority')
            self.assertLessEqual(run.call_count,2)
            self.assertEqual(captured.getvalue(),'CI_SYNTHETIC_AUTHORITY_RENDERER failed_test='+name+' raw_output_withheld=true\n')

    def test_authority_validation_is_three_exact_immutable_replay_cases(self):
        prefix='manual_roster_construction_v3::validation_reuse_tests::'
        names=(
            'call_local_validation_preserves_complete_records_and_canonical_identifiers',
            'call_local_validation_rejects_substituted_plan_extension_attempt_and_amounts',
            'call_local_validation_keeps_every_consume_join_and_revalidates_each_call',
        )
        self.assertEqual(output.AUTHORITY_VALIDATION_TESTS,tuple(prefix+name for name in names))
        self.assertEqual(len(set(output.AUTHORITY_VALIDATION_TESTS)),3)
        self.assertTrue(set(output.AUTHORITY_VALIDATION_TESTS).isdisjoint(output.AUTHORITY_RENDERER_TESTS))
        base=ROOT/'crates/wholepact-authority/src'
        parent=(base/'manual_roster_construction_v3.rs').read_text()
        source=(base/'manual_roster_construction_v3_validation_reuse_tests.rs').read_text()
        self.assertIn('#[path = "manual_roster_construction_v3_validation_reuse_tests.rs"]\nmod validation_reuse_tests;',parent)
        for name in names:
            self.assertEqual(len(re.findall(r'#\[test\]\s+fn '+name+r'\(',source)),1)
        fixture='../../wholepact-signer/src/consent_journal/fixtures/common-context-authority-audit.synthetic.json'
        self.assertIn('"'+fixture+'"',source)
        self.assertTrue((base/fixture).is_file())
        self.assertIn('history.validate().unwrap();',source)
        runner=(ROOT/'scripts/ci-synthetic-output.py').read_text()
        self.assertIn("elif sys.argv[2]=='authority-rendering':\n            run_authority_rendering(str(exe))\n            run_authority_validation(str(exe))",runner)

    def test_authority_validation_runs_exact_cases_with_separate_bound_and_summary(self):
        calls=[]
        def fake_run(argv, **kwargs):
            calls.append((argv,kwargs))
            name=argv[2]
            self.assertIn(name,output.AUTHORITY_VALIDATION_TESTS)
            self.assertEqual(argv[:2],['/verified/authority','--exact'])
            self.assertEqual(argv[3],'--test-threads=1')
            if argv[-1]=='--list':
                self.assertEqual(len(argv),5)
                self.assertEqual(kwargs,dict(capture_output=True,timeout=30,check=True))
                return output.subprocess.CompletedProcess(argv,0,(name+': test\n\n1 test, 0 benchmarks\n').encode(),b'')
            self.assertEqual(len(argv),4)
            self.assertEqual(kwargs,dict(stdout=output.subprocess.PIPE,stderr=output.subprocess.STDOUT,timeout=120))
            return output.subprocess.CompletedProcess(argv,0,b'private immutable fixture output')
        captured=io.StringIO()
        with mock.patch.object(output.resource,'getrlimit',return_value=(0,0)), \
             mock.patch.object(output.subprocess,'run',side_effect=fake_run), \
             contextlib.redirect_stdout(captured):
            output.run_authority_validation('/verified/authority')
        self.assertEqual([argv[2] for argv,_ in calls],[name for name in output.AUTHORITY_VALIDATION_TESTS for _ in range(2)])
        self.assertEqual(captured.getvalue(),'CI_SYNTHETIC_AUTHORITY_VALIDATION passed=3 immutable_replay_cases=3 native_payment_verified=false raw_output_discarded=true\n')

    def test_authority_validation_missing_failed_or_timed_out_refuses_without_raw_output(self):
        name=output.AUTHORITY_VALIDATION_TESTS[0]
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
                with self.assertRaises(Exception): output.run_authority_validation('/verified/authority')
            self.assertLessEqual(run.call_count,2)
            self.assertEqual(captured.getvalue(),'CI_SYNTHETIC_AUTHORITY_VALIDATION failed_test='+name+' raw_output_withheld=true\n')

    def test_ci_temporary_socket_path_budget(self):
        # Includes this runner's extra short TMPDIR layer, not merely /tmp.
        for inner in ['wholepact-born-manual-ipc-','wholepact-born-stop-','.tmp']:
            path='/tmp/wpc.aaaaaa/wp-pty-bbbbbb/'+inner+'cccccc/requests-'+'0'*24+'.sock'
            self.assertLess(len(path.encode()),108)


class PublicTimingTests(unittest.TestCase):
    def record(self, complete=True):
        row=dict(version=1,complete=complete,invalid=False,host_dump_complete=complete,
                 signer_dump_complete=complete,inclusive_aggregates=True,landmarks=[],aggregates=[])
        if complete:
            row['landmarks']=[dict(kind='landmark',phase=p,ordinal=o,start_ms=None,end_ms=None,errors=0)
                              for p,o in output.TIMING_LANDMARK_SLOTS]
            row['aggregates']=[dict(kind='aggregate',phase=p,started=0,completed=0,errors=0,total_ms=0,max_ms=0)
                               for p in output.TIMING_AGGREGATE_PHASES]
        return row

    def line(self, row):
        return output.TIMING_PREFIX+json.dumps(row,separators=(',',':'))+']'

    def test_timing_complete_dump_preserves_missing_unfinished_and_error_distinctions(self):
        missing=self.record(False)
        self.assertEqual(output.public_timing(json.dumps(missing)),missing)
        row=self.record()
        row['landmarks'][0].update(start_ms=0,end_ms=None)
        row['landmarks'][1].update(start_ms=2,end_ms=9,errors=1)
        row['aggregates'][0].update(started=3,completed=2,errors=1,total_ms=19,max_ms=12)
        self.assertEqual(output.public_line(self.line(row).encode(),'fixed'),('timing',row))
        self.assertTrue(row['complete'])  # Catalogue completeness, not finished/successful work.
        row['invalid']=True; row['complete']=False
        self.assertEqual(output.public_timing(json.dumps(row)),row)

    def test_timing_projection_refuses_unknown_duplicate_or_private_fields(self):
        row=self.record()
        mutations=[]
        for key,value in [('version',True),('version',2),('complete',1),('invalid','false'),
                          ('inclusive_aggregates',False),('private','wallet'),('landmarks',{}),
                          ('aggregates',[{}]),('signer_dump_complete',None)]:
            changed=json.loads(json.dumps(row)); changed[key]=value; mutations.append(changed)
        for field,value in [('phase','private'),('ordinal','All'),('kind','aggregate'),('private','secret')]:
            changed=json.loads(json.dumps(row)); changed['landmarks'][0][field]=value; mutations.append(changed)
        for field,value in [('phase','private'),('kind','landmark'),('private','secret')]:
            changed=json.loads(json.dumps(row)); changed['aggregates'][0][field]=value; mutations.append(changed)
        for field in ('landmarks','aggregates'):
            changed=json.loads(json.dumps(row)); changed[field][1]=changed[field][0]; mutations.append(changed)
        for changed in mutations:
            with self.assertRaises(ValueError): output.public_timing(json.dumps(changed))
            self.assertEqual(output.public_line(self.line(changed).encode(),'fixed'),('timing_invalid',None))
        for text in [json.dumps(row).replace('"version": 1','"version": 1, "version": 1'),
                     json.dumps(row).replace('"errors": 0','"errors": 0, "errors": 0',1)]:
            with self.assertRaises(ValueError): output.public_timing(text)
        self.assertEqual(output.public_line((self.line(row)+' private').encode(),'fixed'),('timing_invalid',None))
        self.assertEqual(output.public_line((output.TIMING_PREFIX+'['*2000+'0'+']'*2000+']').encode(),'fixed'),('timing_invalid',None))

    def test_timing_numeric_limits_and_relations_are_strict(self):
        for field,value in [('start_ms',True),('start_ms',-1),('start_ms',900001),('end_ms',0),('errors',1),('errors',False)]:
            row=self.record(); row['landmarks'][0][field]=value
            with self.assertRaises(ValueError): output.public_timing(json.dumps(row))
        for field,value in [('started',True),('started',-1),('started',1000001),('completed',1),
                            ('errors',1),('total_ms',1),('max_ms',1),('max_ms',900000001)]:
            row=self.record(); row['aggregates'][0][field]=value
            with self.assertRaises(ValueError): output.public_timing(json.dumps(row))
        for value in [float('nan'),float('inf'),1.0]:
            row=self.record(); row['aggregates'][0]['started']=value
            with self.assertRaises(ValueError): output.public_timing(json.dumps(row))
        row=self.record(); row['landmarks'][0].update(start_ms=9,end_ms=8)
        with self.assertRaises(ValueError): output.public_timing(json.dumps(row))
        row=self.record(); row['aggregates'][0].update(started=2,completed=2,total_ms=3,max_ms=4)
        with self.assertRaises(ValueError): output.public_timing(json.dumps(row))
        row=self.record(); row['complete']=False
        self.assertEqual(output.public_timing(json.dumps(row)),row)  # Conservative incomplete drain.
        row=self.record(False); row['complete']=True
        with self.assertRaises(ValueError): output.public_timing(json.dumps(row))

    def test_timing_maximal_fixed_catalogue_fits_original_physical_line_bound(self):
        row=self.record()
        for item in row['landmarks']: item.update(start_ms=900000,end_ms=900000,errors=1)
        for item in row['aggregates']: item.update(started=1000000,completed=1000000,errors=1000000,total_ms=900000000,max_ms=900000000)
        line=self.line(row).encode()
        self.assertLess(len(line),8192)
        self.assertEqual(output.public_line(line,'fixed'),('timing',row))
        framing=output.BoundedLines()
        self.assertEqual(framing.feed(b'private'+b'x'*8200+line[:40]),[])
        self.assertEqual(framing.feed(line[40:]+b'\n'+line+b'\n'),[line])
        self.assertIsNone(output.public_line(b'private '+line,'fixed'))
        self.assertIsNone(output.public_line(b'[JOINED_TIMING_V1 {"private":"secret"}]','fixed'))
        for prefix in (b'', b'test fixed ... '):
            self.assertEqual(output.public_line(prefix+b'[JOINED_TIMING '+bytes([255])+b']','fixed'),('timing_invalid',None))
        with self.assertRaises(UnicodeError): output.public_line(b'private '+bytes([255]),'fixed')

    def run_fake(self, timing_lines, status=101, verified=True):
        name=output.TESTS['full'][0]
        core='[JOINED_CORE_POLICY inherited_limit=Zero collector=Pipe process_dumpability=Unchanged crash_copy_absence_verified=false]'
        cleanup=('[JOINED_CLEANUP group_signal=AlreadyAbsentWhileLeaderOwned group_absence=OriginalGroupAbsentObserved '
                 'direct_child=Reaped root_cleanup='+('ClosedAndAbsenceVerified' if verified else 'CloseOrAbsenceUnverified')+
                 f' exit=Some({status}) signal=None core_dumped=false]')
        failure='[JOINED_FAILURE exit=Some(101) signal=None core_dumped=false inputs=1/204 reason=ChildExit static_boundaries=EndInvariant:HostReceipt]'
        rows=[core,cleanup,*timing_lines]
        if status: rows.append(failure)
        else:
            # Use existing exact valid synthetic receipt; no private payload.
            rows.append(output.MARKER+json.dumps(PublicOutputTests().record()))
        payload=('\n'.join(rows)+'\n').encode()
        stream=mock.Mock(); stream.fileno.return_value=7
        process=mock.Mock(stdout=stream); process.wait.return_value=status
        listed=output.subprocess.CompletedProcess([],0,(name+': test\n\n1 test, 0 benchmarks\n').encode(),b'')
        captured=io.StringIO()
        with mock.patch.object(output.resource,'getrlimit',return_value=(0,0)), \
             mock.patch.object(output.subprocess,'run',return_value=listed), \
             mock.patch.object(output.subprocess,'Popen',return_value=process), \
             mock.patch.object(output.select,'select',return_value=([stream],[],[])), \
             mock.patch.object(output.os,'read',side_effect=[payload,b'']), \
             mock.patch.dict(output.os.environ,{},clear=True), contextlib.redirect_stdout(captured):
            if status or not verified:
                with self.assertRaises(RuntimeError): output.run('/verified/host','full')
            else: output.run('/verified/host','full')
        process.kill.assert_not_called()
        return captured.getvalue()

    def test_timing_is_retained_on_actual_failure_only_after_verified_cleanup(self):
        text=self.run_fake([self.line(self.record())])
        self.assertIn('[JOINED_TIMING ',text)
        self.assertLess(text.index('[JOINED_CLEANUP '),text.index('[JOINED_TIMING '))
        self.assertNotIn('phase=full passed=true',text)
        self.assertNotIn('[JOINED_TIMING ',self.run_fake([self.line(self.record())],verified=False))

    def test_invalid_duplicate_or_missing_timing_never_changes_success_predicate(self):
        valid=self.line(self.record())
        for lines,marker in [([valid,valid],'invalid=true'),(['[JOINED_TIMING {"private":"secret"}]'],'invalid=true'),([], 'missing=true')]:
            text=self.run_fake(lines,status=0)
            self.assertIn('CI_SYNTHETIC_TIMING '+marker,text)
            self.assertNotIn('private',text); self.assertNotIn('secret',text)
            self.assertIn('phase=full passed=true cleanup_verified=true',text)
        text=self.run_fake([valid],status=0)
        self.assertIn('[JOINED_TIMING ',text)
        self.assertIn('phase=full passed=true cleanup_verified=true',text)

    def test_timing_catalogues_and_exact_test_registrations_match_actual_sources(self):
        host=(ROOT/'crates/wholepact-native-host/src/host/synthetic_roster_timing_v1.rs').read_text()
        signer=(ROOT/'crates/wholepact-signer/src/native_ui/born_manual_roster_v2/synthetic_timing_v1.rs').read_text()
        def variants(name):
            body=host.split('names! { '+name+' {',1)[1].split('} }',1)[0]
            return tuple(re.findall(r'\b[A-Z][A-Za-z0-9_]+\b',body))
        self.assertEqual(variants('Phase'),output.TIMING_LANDMARK_PHASES)
        self.assertEqual(variants('AggregatePhase'),output.TIMING_AGGREGATE_PHASES)
        phases=tuple(re.findall(r'"([A-Z][A-Za-z0-9]+)"',signer.split('const PHASES:',1)[1].split('];',1)[0]))
        self.assertEqual(set(phases),set(output.TIMING_AGGREGATE_PHASES))
        self.assertEqual(len(phases),16); self.assertEqual(len(output.TIMING_LANDMARK_SLOTS),27)
        for names,source,prefix in [(output.SIGNER_TIMING_TESTS,signer,'native_ui::born_manual_roster_v2::synthetic_timing_v1::tests::'),
                                    (output.TIMING_HOST_TESTS,host,'host::synthetic_roster_timing_v1::tests::')]:
            self.assertEqual(len(names),3 if names is output.SIGNER_TIMING_TESTS else 5)
            for name in names:
                self.assertTrue(name.startswith(prefix))
                self.assertEqual(len(re.findall(r'#\[test\]\s+fn '+name.rsplit('::',1)[1]+r'\(',source)),1)
        source=(ROOT/'scripts/ci-synthetic-output.py').read_text()
        self.assertIn(' + SIGNER_TIMING_TESTS + SIGNER_DURABLE_LABEL_TESTS + SIGNER_DURABLE_RECEIPT_TESTS:',source)
        self.assertIn(' + TIMING_HOST_TESTS + (DURABLE_PROVIDER_METADATA_TEST,):',source)
        self.assertIn('CI_SYNTHETIC_PURE passed=44 ',source)
        self.assertIn('timing_counter_cases=3',source)
        self.assertIn("if status!=0 or not cleanup or cores!=1 or failures or (phase=='full' and outcome is None):",source)
        self.assertNotIn('eprintln!',signer)
        self.assertIn('let _ = writeln!',signer)

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

    def test_all_three_build_failures_keep_original_status_and_never_fallback(self):
        shell=(ROOT/'scripts/ci-synthetic-linux.sh').read_text()
        for phase,filename,seconds,package in [('host','build-metadata.jsonl',3600,'wholepact-native-host'),
                                               ('signer','signer-build-metadata.jsonl',1200,'wholepact-signer'),
                                               ('authority','authority-build-metadata.jsonl',1200,'wholepact-authority')]:
            start=f'if timeout --signal=TERM --kill-after=30s {seconds}s rustup run 1.99.0 cargo test --locked --release -p {package} --all-features --lib --no-run --message-format=json > "$build_root/{filename}"; then'
            self.assertEqual(shell.count(start),1)
            body=shell[shell.index(start):].split('\nfi',1)[0]
            self.assertIn('else\n  build_status=$?\n',body)
            self.assertIn(f'python3 -B scripts/ci-synthetic-build-errors.py "$build_root/{filename}" {phase} || true\n  exit "$build_status"',body)

class DurableEndpointGateTests(unittest.TestCase):
    success='CI_SYNTHETIC_SIGNER_DURABLE_ENDPOINT passed=1 endpoint_cycles=2 native_payment_verified=false runtime_root_cleanup_pending=true raw_output_discarded=true\n'
    failure='CI_SYNTHETIC_SIGNER_DURABLE_ENDPOINT passed=false cleanup_unverified=true raw_output_withheld=true\n'

    def listing(self):
        return (output.SIGNER_DURABLE_ENDPOINT_TEST+': test\n\n1 test, 0 benchmarks\n').encode()

    def run_mocked(self, phases, *, failed=False, environment=None, core=0, expire_phase=None):
        """All process, pipe, clock and core observations are inert mocks."""
        processes=[]; payloads={}; phase_for_fd={}; active=[None]
        for index,phase in enumerate(phases):
            process=mock.Mock()
            process.stdout=mock.Mock()
            process.stdout.fileno.return_value=100+index*2
            process.stderr=mock.Mock() if index==0 else None
            if process.stderr is not None: process.stderr.fileno.return_value=101
            process.wait.return_value=phase.get('status',0)
            if 'wait' in phase: process.wait.side_effect=phase['wait']
            if 'kill' in phase: process.kill.side_effect=phase['kill']
            processes.append(process)
            for stream,key in [(process.stdout,'stdout'),(process.stderr,'stderr')]:
                if stream is not None:
                    payloads[stream.fileno()]=phase.get(key,b'')
                    phase_for_fd[stream.fileno()]=phase

        def popen(argv,**kwargs):
            index=spawn.call_count-1; active[0]=index
            self.assertEqual(argv,['/verified/signer','--exact',output.SIGNER_DURABLE_ENDPOINT_TEST,
                                   '--test-threads=1','--list' if index==0 else '--nocapture'])
            self.assertEqual(kwargs,dict(stdin=output.subprocess.DEVNULL,stdout=output.subprocess.PIPE,
                                         stderr=output.subprocess.PIPE if index==0 else output.subprocess.STDOUT))
            return processes[index]

        def read(fd,size):
            self.assertGreater(size,0); self.assertLessEqual(size,65536)
            if 'read' in phase_for_fd[fd]: raise phase_for_fd[fd]['read']
            chunk=payloads[fd][:size]; payloads[fd]=payloads[fd][size:]
            if not chunk and phase_for_fd[fd].get('expire_at_eof'):
                clock.return_value=31 if active[0]==0 else 121
            return chunk

        def select(streams,write,error,seconds):
            self.assertEqual((write,error),([],[]))
            self.assertGreater(seconds,0); self.assertLessEqual(seconds,0.2)
            if active[0]==expire_phase:
                clock.return_value=31 if active[0]==0 else 121
                return [],[],[]
            return streams[:],[],[]

        captured=io.StringIO()
        env={'GITHUB_ACTIONS':'true','RUNNER_OS':'Linux'} if environment is None else environment
        with mock.patch.dict(output.os.environ,env,clear=True), \
             mock.patch.object(output.sys,'platform','linux'), \
             mock.patch.object(output.resource,'getrlimit',return_value=(core,core)), \
             mock.patch.object(output.subprocess,'Popen',side_effect=popen) as spawn, \
             mock.patch.object(output.subprocess,'run',side_effect=AssertionError('no unmocked runner')), \
             mock.patch.object(output.os,'read',side_effect=read), \
             mock.patch.object(output.select,'select',side_effect=select), \
             mock.patch.object(output.time,'monotonic',return_value=0) as clock, \
             contextlib.redirect_stdout(captured), contextlib.redirect_stderr(captured):
            if failed:
                with self.assertRaisesRegex(RuntimeError,'^CI-only endpoint regression failed; details withheld$'):
                    output.run_signer_durable_endpoint('/verified/signer')
            else:
                output.run_signer_durable_endpoint('/verified/signer')
        self.assertEqual(captured.getvalue(),self.failure if failed else self.success)
        self.assertNotIn('cleanup_verified=true',captured.getvalue())
        for process in processes[:spawn.call_count]:
            process.stdout.close.assert_called_once_with()
            if process.stderr is not None: process.stderr.close.assert_called_once_with()
        return processes,spawn

    def test_endpoint_selection_is_one_nonignored_ci_only_case_not_pure(self):
        name='native_ui::runtime::durable_entry_v1::tests::durable_endpoint_is_external_preserves_inventory_and_drains_before_cleanup'
        self.assertEqual(output.SIGNER_DURABLE_ENDPOINT_TEST,name)
        source=(ROOT/'crates/wholepact-signer/src/native_ui/runtime/durable_entry_v1.rs').read_text()
        self.assertEqual(len(re.findall(r'#\[test\]\s+fn '+name.rsplit('::',1)[1]+r'\(',source)),1)
        self.assertIn('for _ in 0..2 {',source)
        for key,selection in vars(output).items():
            if key.endswith('_TESTS') and isinstance(selection,tuple): self.assertNotIn(name,selection)
        self.assertNotIn(name,[item[0] for item in output.TESTS.values()])
        self.assertNotEqual(name,output.STORAGE_BOOTSTRAP_TEST)
        runner=(ROOT/'scripts/ci-synthetic-output.py').read_text()
        self.assertIn("elif sys.argv[2]=='signer-durable-endpoint': run_signer_durable_endpoint(str(exe))",runner)

    def test_endpoint_gate_follows_signer_validation_and_preserves_final_cleanup(self):
        shell=(ROOT/'scripts/ci-durable-native-linux.sh').read_text()
        call='python3 -B scripts/ci-synthetic-output.py "$signer_executable" signer-durable-endpoint'
        self.assertEqual(shell.count(call),1)
        previous='python3 -B scripts/ci-synthetic-output.py "$signer_executable" signer-validation'
        self.assertIn(previous+'\n'+call,shell)
        self.assertLess(shell.index('cargo test --locked --release -p wholepact-signer --all-features --lib --no-run'),shell.index(call))
        self.assertLess(shell.index('export TMPDIR="$runtime_root"'),shell.index(call))
        self.assertLess(shell.index(call),shell.index('python3 -B scripts/ci-synthetic-output.py "$authority_executable" authority-rendering'))
        self.assertLess(shell.index(call),shell.index('rmdir -- "$runtime_root"\ntrap - EXIT'))
        self.assertLess(shell.index('rmdir -- "$runtime_root"\ntrap - EXIT'),shell.index('All listed regressions and synthetic-only'))
        self.assertIn('set -euo pipefail',shell)
        self.assertIn('trap finish EXIT',shell)
        self.assertNotIn('signer-durable-endpoint',(ROOT/'scripts/ci-synthetic-linux.sh').read_text())

    def test_endpoint_success_drains_but_never_publishes_runtime_text(self):
        private=b'private wallet /private/path\nthread panicked\n\xff\n[JOINED_CLEANUP cleanup_verified=true]\n'
        processes,spawn=self.run_mocked([{'stdout':self.listing()},{'stdout':private}])
        self.assertEqual(spawn.call_count,2)
        for process,seconds in zip(processes,(30,120)):
            process.wait.assert_called_once_with(timeout=seconds)
            process.kill.assert_not_called()

    def test_endpoint_requires_ci_and_own_zero_core_limit_before_spawn(self):
        for environment,core in [({},0),({'GITHUB_ACTIONS':'false','RUNNER_OS':'Linux'},0),
                                 ({'GITHUB_ACTIONS':'true','RUNNER_OS':'Windows'},0),
                                 ({'GITHUB_ACTIONS':'true','RUNNER_OS':'Linux'},1)]:
            with self.subTest(environment=environment,core=core):
                _,spawn=self.run_mocked([],failed=True,environment=environment,core=core)
                spawn.assert_not_called()

    def test_endpoint_listing_rejects_missing_duplicate_stderr_nonutf8_and_nonzero(self):
        cases=[{'stdout':b'0 tests, 0 benchmarks\n'},
               {'stdout':self.listing()*2},
               {'stdout':self.listing()+b'private suffix'},
               {'stdout':self.listing(),'stderr':b'private listing error'},
               {'stdout':b'\xff'},
               {'stdout':self.listing(),'status':101}]
        for phase in cases:
            with self.subTest(phase=phase):
                processes,spawn=self.run_mocked([phase],failed=True)
                self.assertEqual(spawn.call_count,1)
                processes[0].kill.assert_not_called()

    def test_endpoint_output_limits_are_incremental_and_stop_only_direct_process(self):
        for phase in (0,1):
            limit=8192 if phase==0 else 1024*1024
            cases=[{'stdout':self.listing()},{'stdout':b''}][:phase+1]
            cases[phase]['stdout']=b'x'*(limit+1)
            processes,spawn=self.run_mocked(cases,failed=True)
            self.assertEqual(spawn.call_count,phase+1)
            processes[phase].kill.assert_called_once_with()
            processes[phase].wait.assert_called_once_with(timeout=5)
        # The runtime limit is inclusive and arbitrary invalid bytes are inert.
        self.run_mocked([{'stdout':self.listing()},{'stdout':b'\xff'*(1024*1024)}])

    def test_endpoint_failed_exit_never_passes_or_claims_cleanup(self):
        for status in (1,101,-9):
            processes,_=self.run_mocked([{'stdout':self.listing()},
                                        {'stdout':b'private panic /wallet','status':status}],failed=True)
            processes[1].kill.assert_not_called()

    def test_endpoint_each_original_deadline_is_finite_and_forced_stop_unverified(self):
        for phase in (0,1):
            processes,_=self.run_mocked([{'stdout':self.listing()},{'stdout':b''}],
                                       failed=True,expire_phase=phase)
            processes[phase].kill.assert_called_once_with()
            processes[phase].wait.assert_called_once_with(timeout=5)

    def test_endpoint_eof_is_not_success_until_exact_exit_observed(self):
        error=output.subprocess.TimeoutExpired('private command /wallet',120,output=b'private panic')
        processes,_=self.run_mocked([{'stdout':self.listing()},
                                    {'stdout':b'','wait':[error,0]}],failed=True)
        processes[1].kill.assert_called_once_with()
        self.assertEqual(processes[1].wait.call_args_list,[mock.call(timeout=120),mock.call(timeout=5)])
        for phase in (0,1):
            cases=[{'stdout':self.listing()},{'stdout':b''}]
            cases[phase]['expire_at_eof']=True
            processes,_=self.run_mocked(cases,failed=True)
            processes[phase].kill.assert_called_once_with()
            processes[phase].wait.assert_called_once_with(timeout=5)

    def test_endpoint_io_and_failed_kill_reap_exceptions_stay_private(self):
        private=OSError('private wallet /secret/panic')
        processes,_=self.run_mocked([{'stdout':self.listing()},
                                    {'read':private,'kill':private,'wait':[private]}],failed=True)
        processes[1].kill.assert_called_once_with()
        processes[1].wait.assert_called_once_with(timeout=5)

if __name__=='__main__':
    unittest.main()
