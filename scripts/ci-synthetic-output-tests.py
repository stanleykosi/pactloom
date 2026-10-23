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

    def test_durable_acquire_reply_loss_is_exact_ignored_and_preserves_every_old_phase(self):
        expected={
            'durable-delivery-admission': ('durable_proposal_v1::delivery_admission_v2::durable_delivery_native_v3_admission_reopens_original_after_process_death',1080,True),
            'durable-private-reopen': ('durable_proposal_v1::private_fixed_v2::private_workspace_actual_process_death_reopens_same_fixed_proof',1080,True),
            'initial': ('initial_joined_v3::actual_three_born_initial_roster_publications_preserve_refusal',300,False),
            'full': ('full_payment_inputs_v1::actual_three_born_full_payment_uses_one_original_synthetic_path',1080,True),
            'durable-owner-reopen': ('durable_proposal_v1::durable_proposal_native_owner_reopen_retains_exact_fixed_proof',1080,True),
            'durable-fixed-signing': ('durable_proposal_v1::durable_proposal_native_fixed_signing_retains_exact_results',1080,True),
            'durable-acquire-reply-loss': ('durable_proposal_v1::durable_proposal_native_acquire_reply_loss_retries_original_session',1080,True),
        }
        self.assertEqual(set(output.TESTS),set(expected))
        self.assertEqual(len({name for name,_ in output.TESTS.values()}),7)
        self.assertEqual(output.DURABLE_DIAGNOSTIC_PHASES,
                         frozenset(('durable-fixed-signing','durable-acquire-reply-loss')))
        for phase,(suffix,seconds,ignored) in expected.items():
            name=output.PREFIX+suffix
            self.assertEqual(output.phase_selection(phase),
                             (name,seconds,['--exact',name,'--test-threads=1']+(['--ignored'] if ignored else [])))
        for phase in ('durable-acquire','durable-acquire-reply-loss-v1','durable-acquire-reply-loss ',
                      'durable-acquire-reply-loss*','durable-proposal-native-acquire-reply-loss-v1','*'):
            with self.assertRaises(KeyError): output.phase_selection(phase)

    def test_durable_acquire_reply_loss_producer_selector_stage_and_cleanup_match(self):
        base=ROOT/'crates/wholepact-native-host/src/host/manual_enrollment/command/roster_publication_v2/sequential_construction_v3_qualification'
        source=(base/'durable_proposal_v1.rs').read_text()
        name=output.TESTS['durable-acquire-reply-loss'][0].rsplit('::',1)[1]
        stage='durable-proposal-native-acquire-reply-loss-v1'
        matches=re.findall(r'#\[test\]\s*#\[ignore = "[^"\n]+"\]\s*fn '+name+r'\(\)\s*\{(.*?)\n\}',source,re.S)
        self.assertEqual(len(matches),1)
        self.assertIn('foreground_child("'+stage+'", &inputs())',matches[0])
        self.assertEqual(source.count('fn '+name+'()'),1)
        wrapper=source.split('fn exercise_acquire_reply_loss_stage(',1)[1].split('\n}',1)[0]
        self.assertIn('initial::prepare(terminal)?',wrapper)
        self.assertIn('preproof::exercise_with_acquire_reply_loss(initial)',wrapper)
        parent=base.with_suffix('.rs').read_text()
        safety=parent.split('let safety_seconds = if matches!(',1)[1].split('let deadline =',1)[0]
        self.assertEqual(set(re.findall(r'"([a-z0-9-]+)"',safety)),{
            'three-born-retained-inputs-v3','three-born-all-observations-v3',
            'three-born-constructed-checkpoint-v3','three-born-full-payment-v1',
            'durable-proposal-native-owner-reopen-v1','durable-proposal-native-fixed-signing-v1',stage})
        self.assertRegex(safety,r'\)\s*\{\s*900\s*\}\s*else\s*\{\s*180\s*\}')
        dispatch=parent.split('if stage == "'+stage+'" {',1)[1].split('\n    }',1)[0]
        self.assertIn('durable_proposal_v1::exercise_acquire_reply_loss_stage(terminal).unwrap();',dispatch)
        self.assertIn('return;',dispatch)
        gate=parent.split('if (stage == "durable-proposal-native-fixed-signing-v1"',1)[1].split('\n    if outcome.is_err()',1)[0]
        self.assertEqual(re.findall(r'\|\| stage == "([a-z0-9-]+)"',gate),[stage])
        self.assertIn('&& process.verified()',gate)
        self.assertIn('&& root_cleanup == TemporaryRootCleanupV1::ClosedAndAbsenceVerified',gate)
        for method in ('history_measurement_lines','admission_diagnostic_lines','durable_flow_lines','durable_lifecycle_lines'):
            self.assertRegex(gate,r'\b'+method+r'\s*\(\s*\)')
        self.assertNotIn('outcome.is_ok()',gate)
        self.assertEqual(parent.count('"'+stage+'"'),3)

    def test_durable_acquire_reply_loss_reuses_only_same_compiled_binary_in_separate_gate(self):
        shell=(ROOT/'scripts/ci-durable-native-linux.sh').read_text()
        call='TMPDIR="$runtime_root" python3 -B scripts/ci-synthetic-output.py "$executable" durable-acquire-reply-loss'
        self.assertEqual(shell.count(call),1)
        self.assertEqual(shell.count('cargo test --locked --release -p wholepact-native-host '),1)
        self.assertLess(shell.index('sha256sum "$executable"'),shell.index(call))
        self.assertLess(shell.index('"$executable" durable-fixed-signing'),shell.index(call))
        self.assertLess(shell.index(call),shell.index('cargo test --locked --release -p wholepact-signer '))
        self.assertIn('original pending-session Acquire reply-loss recovery checks passed;',shell)
        self.assertIn('No public-chain settlement, attended GUI, Windows or production activation claimed.',shell)
        self.assertIn('set -euo pipefail',shell)
        self.assertIn('export CARGO_HOME="$build_root/cargo" CARGO_TARGET_DIR="$build_root/target"',shell)
        # Only the separately bounded, exact CI loopback preflight may run an
        # ignored test. Native phases and signer regressions remain unchanged.
        prefix, wave_and_rest = shell.split("<<'PY_WAVE'\n", 1)
        wave, suffix = wave_and_rest.split('\nPY_WAVE\n', 1)
        self.assertNotIn('--ignored', prefix + suffix)
        self.assertEqual(shell.count("<<'PY_WAVE'"), 1)
        self.assertIn("name = 'host::financial::private_durable_fixed_v2::observation_wave_v3_tests::observation_wave_actual_localhost_requests_overlap_before_responses'", wave)
        self.assertEqual(wave.count('subprocess.run('), 2)
        self.assertIn("[sys.argv[1], name, '--ignored', '--exact', '--list'], capture_output=True, text=True, timeout=15", wave)
        self.assertIn("[sys.argv[1], name, '--ignored', '--exact', '--test-threads=1'], capture_output=True, text=True, timeout=30", wave)
        self.assertEqual(wave.count('--ignored'), 2)
        self.assertIn("== [name + ': test']", wave)
        self.assertIn("result.returncode == 0 and 'test result: ok. 1 passed; 0 failed;' in result.stdout", wave)
        self.assertNotIn('print(result', wave)
        self.assertNotIn('print(listed', wave)
        self.assertIn('sys.exit(1)', wave)
        self.assertLess(shell.index("<<'PY_WAVE'"), shell.index('"$executable" durable-private-reopen'))
        self.assertIn('timeout-minutes: 150',(ROOT/'.github/workflows/durable-native-linux.yml').read_text())

    def test_durable_acquire_reply_loss_producer_requires_retry_receipt_joined_audit_and_no_signing(self):
        base=ROOT/'crates/wholepact-native-host/src/host/manual_enrollment/command/roster_publication_v2/sequential_construction_v3_qualification/durable_proposal_v1'
        leaf=(base/'fixed_signing/acquire_reply_loss.rs').read_text().split('#[cfg(test)]',1)[0]
        ordered=(
            '.send(Command::AcquireDurableWriterExpectingReplyLoss(index))',
            'observation.is_expected_loss()',
            '.send(Command::RetryDurableWriterAfterReplyLoss(index))',
            'let retry_receipt = match worker.receive()',
            'Reply::DurableAcquireRetried {',
            'drop(expected_loss);',
            '.send(Command::CloseDurable(index))',
            'drop(client);',
            'drop(financial_server);',
            '.audit_committed_durable_payment_reply_loss_v1(fault_observation, &retry_receipt)',
            'report.original_acquire_committed',
            'drop(retry_receipt);',
            'trace.complete();',
            'Ok(())',
        )
        recovery=leaf[leaf.index(ordered[0]):]
        positions=[recovery.index(item) for item in ordered]
        self.assertEqual(positions,sorted(positions))
        self.assertEqual(leaf.count(ordered[0]),1)
        self.assertEqual(leaf.count(ordered[2]),1)
        for forbidden in ('WriterReconcileComplete','Command::ReconcileDurableWriter',
                          'Command::ConfigureDurableWallet','Command::SignDurable',
                          'B::DurableHostWriterReconcile','B::DurableHostSign'):
            self.assertNotIn(forbidden,leaf)
        worker=(base/'worker.rs').read_text()
        expected=worker.split('(C::AcquireDurableWriterExpectingReplyLoss(_),',1)[1].split('(C::RetryDurableWriterAfterReplyLoss(_),',1)[0]
        self.assertIn('Ok(observation) => observation,',expected)
        self.assertIn('State::Durable(entry)',expected)
        self.assertIn('R::DurableAcquireReplyLost { index, observation }',expected)
        self.assertIn('failure.finalize_after_drain();',expected)
        self.assertIn('return Err(durable_flow_error(',expected)
        self.assertNotIn('diagnostic::emit',expected)

    def test_durable_runner_separates_old_owner_baseline_from_new_process_restart(self):
        shell=(ROOT/'scripts/ci-durable-native-linux.sh').read_text()
        workflow=(ROOT/'.github/workflows/durable-native-linux.yml').read_text()
        self.assertIn('refs/heads/qualification/durable-proposal-v1',shell)
        self.assertIn('branches: [qualification/durable-proposal-v1]',workflow)
        self.assertIn('python3 -B scripts/ci-synthetic-output.py "$executable" durable-owner-reopen',shell)
        self.assertNotIn('python3 -B scripts/ci-synthetic-output.py "$executable" full',shell)
        self.assertIn('The old owner/session baseline is not process-restart evidence.',shell)

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

    def test_signer_admission_diagnostics_are_finite_and_redacted(self):
        self.assertEqual(len(output.SIGNER_ADMISSION_BOUNDARIES),14)
        self.assertFalse(output.SIGNER_ADMISSION_BOUNDARIES & output.DURABLE_HOST_BOUNDARIES)
        for label in output.SIGNER_ADMISSION_BOUNDARIES:
            self.assertTrue(output.safe_failure(self.failure(label+':SignerReviewMismatch')))
            self.assertFalse(output.safe_failure(self.failure(label+':private-account-id')))
            self.assertFalse(output.safe_failure(self.failure(label+':/private/vault')))
        self.assertFalse(output.safe_failure(self.failure('SignerAdmissionUnreviewed:Begin')))

    def test_signer_history_diagnostics_are_finite_and_redacted(self):
        self.assertEqual(len(output.SIGNER_HISTORY_BOUNDARIES),27)
        self.assertFalse(output.SIGNER_HISTORY_BOUNDARIES & output.SIGNER_ADMISSION_BOUNDARIES)
        for label in output.SIGNER_HISTORY_BOUNDARIES:
            self.assertTrue(output.safe_failure(self.failure(label+':SignerUncertain')))
            self.assertFalse(output.safe_failure(self.failure(label+':private-account-id')))
            self.assertFalse(output.safe_failure(self.failure(label+':/private/vault')))
        self.assertFalse(output.safe_failure(self.failure('SignerAdmissionHistoryUnreviewed:Begin')))

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
               'python3 -B scripts/ci-synthetic-output.py "$executable" durable-delivery-admission',
               'python3 -B scripts/ci-synthetic-output.py "$executable" durable-private-reopen',
               'python3 -B scripts/ci-synthetic-output.py "$executable" durable-owner-reopen',
               'python3 -B scripts/ci-synthetic-output.py "$executable" durable-fixed-signing',
               'python3 -B scripts/ci-synthetic-output.py "$executable" durable-acquire-reply-loss']
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

    def test_rolling_preflight_preserves_ten_original_plus_twelve_optional_cases(self):
        base=ROOT/'crates/wholepact-native-host/src/host/manual_enrollment/command/roster_publication_v2'
        source=(base/'sequential_construction_v3_qualification/rolling_transcript_v1.rs').read_text()
        original,delivery=source.split('mod delivery_first_failure_tests {')
        names=re.findall(r'#\[test\]\s+(?:#\[cfg\(feature = "synthetic-born-joined-qualification"\)\]\s+)?fn (\w+)\(',original)
        delivery_names=re.findall(r'#\[test\]\s+fn (\w+)\(',delivery)
        self.assertEqual(tuple(delivery_names),(
            'delivery_first_failure_survives_more_than_64_later_diagnostics',
            'delivery_first_failure_requires_complete_exact_finite_marker',
            'delivery_first_failure_is_opt_in_and_isolated_per_child',
            'delivery_first_failure_yields_to_chunk_budget_and_never_recaptures',
            'delivery_first_failure_yields_to_summary_and_path_metadata_budget',
            'delivery_first_failure_yields_before_existing_optional_capture_budget',
            'delivery_first_failure_yields_before_position_budget_refusals',
            'delivery_first_failure_insufficient_capture_budget_is_sticky',
        ))
        self.assertEqual(len(delivery_names),len(set(delivery_names)))
        all_expected=tuple(output.PREFIX+'rolling_transcript_v1::tests::'+name for name in names)
        self.assertEqual(len(all_expected),22)
        self.assertEqual(set(all_expected),set(output.ROLLING_TRANSCRIPT_TESTS+output.HISTORY_TRANSCRIPT_TESTS+output.ADMISSION_TRANSCRIPT_TESTS+output.FLOW_TRANSCRIPT_TESTS))
        expected=tuple(name for name in all_expected if name not in output.HISTORY_TRANSCRIPT_TESTS+output.ADMISSION_TRANSCRIPT_TESTS+output.FLOW_TRANSCRIPT_TESTS)
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

    def run_fake(self, timing_lines, status=101, verified=True, phase='full', cleanup_present=True):
        name=output.TESTS[phase][0]
        core='[JOINED_CORE_POLICY inherited_limit=Zero collector=Pipe process_dumpability=Unchanged crash_copy_absence_verified=false]'
        cleanup=('[JOINED_CLEANUP group_signal=AlreadyAbsentWhileLeaderOwned group_absence=OriginalGroupAbsentObserved '
                 'direct_child=Reaped root_cleanup='+('ClosedAndAbsenceVerified' if verified else 'CloseOrAbsenceUnverified')+
                 f' exit=Some({status}) signal=None core_dumped=false]')
        failure='[JOINED_FAILURE exit=Some(101) signal=None core_dumped=false inputs=1/204 reason=ChildExit static_boundaries=EndInvariant:HostReceipt]'
        rows=[core]+([cleanup] if cleanup_present else [])+list(timing_lines)
        if status: rows.append(failure)
        elif phase=='full':
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
            if status or not verified or not cleanup_present:
                with self.assertRaises(RuntimeError): output.run('/verified/host',phase)
            else: output.run('/verified/host',phase)
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
        self.assertIn(' + TIMING_HOST_TESTS + (DURABLE_PROVIDER_METADATA_TEST,)',source)
        self.assertIn('CI_SYNTHETIC_PURE passed={len(selected)} ',source)
        self.assertIn('timing_counter_cases=3',source)
        self.assertIn("if status!=0 or not cleanup or cores!=1 or failures or (phase=='full' and outcome is None):",source)
        self.assertNotIn('eprintln!',signer)
        self.assertIn('let _ = writeln!',signer)

class PublicHistoryMeasurementTests(unittest.TestCase):
    base=ROOT/'crates/wholepact-native-host/src/host/manual_enrollment/command/roster_publication_v2/sequential_construction_v3_qualification'

    def record(self):
        source=(self.base/'safe_diagnostics_v1.rs').read_text()
        fixture=re.search(r'const HISTORY_MEASUREMENT_TEST_JSON: &str = r#"(.*?)"#;',source,re.S).group(1)
        return json.loads(fixture)

    def server_record(self, point='BeforeAdmission'):
        return dict(version=1,point=point,age_us=0,remaining_us=0,stopped=False,finished=None,clamped=False)

    def line(self, row, server=False):
        prefix=output.HISTORY_SERVER_MEASUREMENT_PREFIX if server else output.HISTORY_MEASUREMENT_PREFIX
        return prefix+json.dumps(row,separators=(',',':'))+']'

    def test_history_rust_fixture_and_all_closed_labels_are_accepted(self):
        row=self.record()
        self.assertEqual(output.public_history_measurement(json.dumps(row)),row)
        self.assertEqual(set(row),output.HISTORY_MEASUREMENT_FIELDS)
        for field,values in [('phase',output.HISTORY_PHASES),('check_site',output.HISTORY_CHECK_SITES),
                             ('checkpoint',output.HISTORY_CHECKPOINTS),('selected_limit',output.HISTORY_SELECTED_LIMITS)]:
            for value in values:
                changed=self.record(); changed[field]=value
                if field=='phase': changed['page_ordinal']=1 if value=='Page' else None
                self.assertEqual(output.public_history_measurement(json.dumps(changed)),changed)
        for point in output.HISTORY_SERVER_POINTS:
            server=self.server_record(point)
            self.assertEqual(output.public_history_server_measurement(json.dumps(server)),server)

    def test_history_null_and_zero_and_incomplete_are_distinct(self):
        row=self.record()
        for field in output.HISTORY_OPTIONAL_DURATIONS | {'phase','page_ordinal','check_site','selected_limit','exchange_cost'}:
            row[field]=None
        row['incomplete']=True
        self.assertEqual(output.public_history_measurement(json.dumps(row)),row)
        for field in output.HISTORY_OPTIONAL_DURATIONS:
            changed=dict(row,**{field:0})
            parsed=output.public_history_measurement(json.dumps(changed))
            self.assertEqual(parsed[field],0)
            self.assertIsNotNone(parsed[field])
        for age in (None,0,600000000):
            for finished in (None,False,True):
                row=self.server_record(); row.update(age_us=age,finished=finished,clamped=True)
                self.assertEqual(output.public_history_server_measurement(json.dumps(row)),row)

    def test_history_requires_every_field_including_nullable_and_flags(self):
        for original,parser in [(self.record(),output.public_history_measurement),
                                (self.server_record(),output.public_history_server_measurement)]:
            for field in original:
                changed=dict(original); del changed[field]
                with self.assertRaises(ValueError): parser(json.dumps(changed))
            for wrong in ([],None,True,dict(original,private='payload')):
                with self.assertRaises(ValueError): parser(json.dumps(wrong))
        for cost in ('history_cost','exchange_cost'):
            for field in output.HISTORY_COST_COUNTS | output.HISTORY_COST_DURATIONS:
                row=self.record(); del row[cost][field]
                with self.assertRaises(ValueError): output.public_history_measurement(json.dumps(row))
            for wrong in ([],True,{},dict(self.record()[cost],private='payload')):
                row=self.record(); row[cost]=wrong
                with self.assertRaises(ValueError): output.public_history_measurement(json.dumps(row))
        row=self.record(); row['history_cost']=None
        with self.assertRaises(ValueError): output.public_history_measurement(json.dumps(row))

    def test_history_rejects_duplicate_keys_at_every_scope(self):
        text=json.dumps(self.record(),separators=(',',':'))
        for changed in [text.replace('"version":1','"version":1,"version":1',1),
                        text.replace('"callback_calls":2','"callback_calls":2,"callback_calls":2',1),
                        text.replace('"callback_calls":1','"callback_calls":1,"callback_calls":1',1),
                        text.replace('"exchange_cost":','"exchange_cost":null,"exchange_cost":',1)]:
            with self.assertRaises(ValueError): output.public_history_measurement(changed)
        text=json.dumps(self.server_record(),separators=(',',':'))
        for field in ('version','age_us','finished'):
            value=json.dumps(self.server_record()[field])
            changed=text.replace('"'+field+'":'+value,'"'+field+'":'+value+',"'+field+'":'+value,1)
            with self.assertRaises(ValueError): output.public_history_server_measurement(changed)

    def test_history_numeric_fields_reject_boolean_negative_float_and_overflow(self):
        fields={field:600000000 for field in output.HISTORY_OPTIONAL_DURATIONS | {'history_elapsed_us','pre_budget_callback_us'}}
        fields.update(version=1,pre_budget_callback_calls=1)
        for field,limit in fields.items():
            for bad in (True,False,-1,limit+1,1.0,float('nan'),float('inf'),float('-inf'),'0',{},[]):
                row=self.record(); row[field]=bad
                with self.assertRaises(ValueError): output.public_history_measurement(json.dumps(row))
        for cost in ('history_cost','exchange_cost'):
            for field in output.HISTORY_COST_COUNTS | output.HISTORY_COST_DURATIONS:
                limit=1000000 if field in output.HISTORY_COST_COUNTS else 600000000
                for bad in (True,False,-1,limit+1,1.0,float('nan'),None,'0'):
                    row=self.record(); row[cost][field]=bad
                    with self.assertRaises(ValueError): output.public_history_measurement(json.dumps(row))
        for ordinal in (True,False,0,-1,4097,1.0,'1'):
            row=self.record(); row.update(phase='Page',page_ordinal=ordinal)
            with self.assertRaises(ValueError): output.public_history_measurement(json.dumps(row))

    def test_history_server_types_and_bounds_are_strict(self):
        for field in ('age_us','remaining_us'):
            for bad in (True,False,-1,600000001,1.0,float('nan'),float('inf'),'0',{}):
                row=self.server_record(); row[field]=bad
                with self.assertRaises(ValueError): output.public_history_server_measurement(json.dumps(row))
        for field in ('stopped','finished','clamped'):
            for bad in (0,1,'false',{},[]):
                row=self.server_record(); row[field]=bad
                with self.assertRaises(ValueError): output.public_history_server_measurement(json.dumps(row))
        for field,bad in [('remaining_us',None),('stopped',None),('clamped',None),('version',True),
                          ('version',0),('version',2),('point',None),('point','Ready')]:
            row=self.server_record(); row[field]=bad
            with self.assertRaises(ValueError): output.public_history_server_measurement(json.dumps(row))

    def test_history_free_form_enums_and_invalid_page_context_are_refused(self):
        for field in ('phase','check_site','checkpoint','selected_limit'):
            for bad in ('private','Snapshot/private','',True,0,[],{}):
                row=self.record(); row[field]=bad
                with self.assertRaises(ValueError): output.public_history_measurement(json.dumps(row))
        for changes in [dict(phase='Page',page_ordinal=None),dict(phase=None,page_ordinal=1),
                        dict(phase='Snapshot',page_ordinal=1),dict(checkpoint=None),
                        dict(clamped=0),dict(incomplete=None)]:
            with self.assertRaises(ValueError): output.public_history_measurement(json.dumps(dict(self.record(),**changes)))

    def test_history_maximal_schema_fits_unchanged_output_bounds(self):
        row=self.record(); row.update(phase='Page',page_ordinal=4096,pre_budget_callback_calls=1,
                                     history_elapsed_us=600000000,pre_budget_callback_us=600000000,clamped=True)
        for field in output.HISTORY_OPTIONAL_DURATIONS: row[field]=600000000
        for field in ('history_cost','exchange_cost'):
            row[field]={key:1000000 for key in output.HISTORY_COST_COUNTS}
            row[field].update({key:600000000 for key in output.HISTORY_COST_DURATIONS})
        self.assertLess(len(self.line(row).encode()),4096)
        self.assertEqual(output.public_line(self.line(row).encode(),'fixed'),('history_measurement',row))
        server=self.server_record(); server.update(age_us=600000000,remaining_us=600000000,finished=True,clamped=True)
        self.assertLess(len(self.line(server,True).encode()),512)
        self.assertEqual(output.public_line(self.line(server,True).encode(),'fixed'),('history_server_measurement',server))
        with self.assertRaises(ValueError): output.public_history_measurement(' '*4097)
        with self.assertRaises(ValueError): output.public_history_server_measurement(' '*513)
        source=(ROOT/'scripts/ci-synthetic-output.py').read_text()
        self.assertRegex(source,r'def public_line\(raw,\s*name\):\s+if len\(raw\)>8192:')
        prefix=output.HISTORY_MEASUREMENT_PREFIX.encode('ascii')
        at_limit=prefix+b' '*(8192-len(prefix)-1)+b']'
        self.assertEqual(output.public_line(at_limit,'fixed'),('history_measurement_invalid',None))
        self.assertIsNone(output.public_line(at_limit+b' ','fixed'))
        self.assertIn('if total > 16*1024*1024:',source)

    def test_history_framing_never_searches_inside_private_text(self):
        for row,server,kind in [(self.record(),False,'history_measurement'),
                                (self.server_record(),True,'history_server_measurement')]:
            line=self.line(row,server)
            for prefix in ('','test fixed ... '):
                self.assertEqual(output.public_line((prefix+line).encode(),'fixed'),(kind,row))
                marker=output.HISTORY_SERVER_MEASUREMENT_PREFIX if server else output.HISTORY_MEASUREMENT_PREFIX
                self.assertEqual(output.public_line(prefix.encode()+marker.encode()+b'\xff]','fixed'),(kind+'_invalid',None))
            self.assertIsNone(output.public_line(('private '+line).encode(),'fixed'))
            for changed in (line+' private',line[:-1],line+line):
                self.assertEqual(output.public_line(changed.encode(),'fixed'),(kind+'_invalid',None))
            framing=output.BoundedLines()
            raw=line.encode(); split=len(raw)//2
            self.assertEqual(framing.feed(raw[:split]),[])
            self.assertEqual(framing.feed(raw[split:]+b'\n'),[raw])
        nested=output.HISTORY_MEASUREMENT_PREFIX+'['*1500+'0'+']'*1500+']'
        self.assertEqual(output.public_line(nested.encode(),'fixed'),('history_measurement_invalid',None))

    def test_history_emits_only_after_cleanup_and_never_changes_original_result(self):
        lines=[self.line(self.record())]+[self.line(self.server_record(point),True) for point in output.HISTORY_SERVER_POINTS]
        fake=PublicTimingTests().run_fake
        failed=fake(lines,phase='durable-fixed-signing')
        for prefix in (output.HISTORY_MEASUREMENT_PREFIX,output.HISTORY_SERVER_MEASUREMENT_PREFIX):
            self.assertIn(prefix,failed)
            self.assertLess(failed.index('[JOINED_CLEANUP '),failed.index(prefix))
            self.assertNotIn(prefix,fake(lines,verified=False,phase='durable-fixed-signing'))
        self.assertNotIn('passed=true',failed)
        for rows in ([],lines,[lines[0],lines[0]],['[HISTORY_MEASUREMENT_V1 {"private":"payload"}]']):
            success=fake(rows,status=0,phase='durable-fixed-signing')
            self.assertIn('phase=durable-fixed-signing passed=true cleanup_verified=true',success)
            self.assertNotIn('private',success); self.assertNotIn('payload',success)
        for phase in ('initial','full','durable-owner-reopen'):
            unrelated=fake(lines,status=0,phase=phase)
            self.assertNotIn(output.HISTORY_MEASUREMENT_PREFIX,unrelated)
            self.assertNotIn(output.HISTORY_SERVER_MEASUREMENT_PREFIX,unrelated)

    def test_history_duplicate_records_are_sticky_and_separate_from_other_timings(self):
        capture=output.HistoryMeasurements()
        row=self.record(); before=self.server_record(); after=self.server_record('AfterAdmission')
        capture.record('history_measurement',row)
        capture.record('history_server_measurement',before)
        capture.record('history_server_measurement',after)
        capture.record('history_measurement',row)
        capture.record('history_server_measurement',before)
        capture.record('history_measurement',row)
        captured=io.StringIO()
        with contextlib.redirect_stdout(captured): capture.emit()
        self.assertEqual(captured.getvalue(),'CI_SYNTHETIC_HISTORY_MEASUREMENT invalid=true details_withheld=true\n'
                         'CI_SYNTHETIC_HISTORY_SERVER_MEASUREMENT invalid=true details_withheld=true\n')
        self.assertEqual(output.public_line(captured.getvalue().splitlines()[0].encode(),'fixed'),('history_measurement_invalid',None))
        self.assertEqual(output.public_line(captured.getvalue().splitlines()[1].encode(),'fixed'),('history_server_measurement_invalid',None))
        self.assertNotIn('JOINED_TIMING',captured.getvalue())

    def test_history_producer_getters_schema_and_closed_enums_correspond(self):
        source=(self.base/'safe_diagnostics_v1.rs').read_text()
        client=source.split('fn history_measurement_json(',1)[1].split('pub(super) fn emit_history_measurement(',1)[0]
        cost=source.split('fn history_cost_json(',1)[1].split('fn history_measurement_json(',1)[0]
        server=source.split('fn history_server_measurement_json(',1)[1].split('pub(super) fn emit_history_server_measurement(',1)[0]
        self.assertEqual(set(re.findall(r'"([a-z_]+)":',client)),output.HISTORY_MEASUREMENT_FIELDS)
        self.assertEqual(set(re.findall(r'"([a-z_]+)":',cost)),output.HISTORY_COST_COUNTS|output.HISTORY_COST_DURATIONS)
        self.assertEqual(set(re.findall(r'"([a-z_]+)":',server)),output.HISTORY_SERVER_MEASUREMENT_FIELDS)
        for field in output.HISTORY_MEASUREMENT_FIELDS-{'version'}:
            self.assertIn('value.'+field+'()',client)
        for field in output.HISTORY_COST_COUNTS|output.HISTORY_COST_DURATIONS:
            self.assertIn('value.'+field+'()',cost)
        authority=(ROOT/'crates/wholepact-authority/src/transport/history_diagnostics_v1.rs').read_text()
        for type_name,values in [('CheckedHistoryPhaseV1',output.HISTORY_PHASES|{'Admission'}|output.FLOW_TRANSPORT_PURPOSE),
            ('CheckedHistoryCheckSiteV1',output.HISTORY_CHECK_SITES),('CheckedHistoryCheckpointV1',output.HISTORY_CHECKPOINTS),
            ('CheckedHistorySelectedLimitV1',output.HISTORY_SELECTED_LIMITS)]:
            mappings=set(re.findall(type_name+r'::([A-Za-z0-9]+) => "([A-Za-z0-9]+)"',source))
            self.assertEqual(mappings,{(value,value) for value in values})
            body=re.search(r'pub enum '+type_name+r'\s*\{([^}]+)\}',authority).group(1)
            self.assertEqual(set(re.findall(r'^\s*([A-Z][A-Za-z0-9]+),',body,re.M)),values)
        for function in ('emit_history_measurement','emit_history_server_measurement'):
            body=source.split('pub(super) fn '+function+'(',1)[1].split('\n}\n',1)[0]
            self.assertIn('let _ = writeln!',body)
            self.assertNotIn('eprintln!',body)
        self.assertNotIn('Debug',client+cost+server)
        self.assertIn('Exchange cost is a subset of history cost',client)

    def test_history_required_nullable_parser_and_exact_cleanup_gate_are_preserved(self):
        source=(self.base/'safe_diagnostics_v1.rs').read_text()
        for struct in ('PublicHistoryMeasurement','PublicHistoryServerMeasurement'):
            body=source.split('struct '+struct+' {',1)[1].split('\n}',1)[0]
            nullable=re.findall(r'^    [a-z_]+: Option<',body,re.M)
            self.assertEqual(body.count('#[serde(deserialize_with = "required_history_nullable")]'),len(nullable))
        parent=self.base.with_suffix('.rs').read_text()
        gate=parent.split('if (stage == "durable-proposal-native-fixed-signing-v1"',1)[1].split('\n    if outcome.is_err()',1)[0]
        self.assertIn('&& process.verified()',gate)
        self.assertIn('&& root_cleanup == TemporaryRootCleanupV1::ClosedAndAbsenceVerified',gate)
        self.assertRegex(gate,r'\btranscript\s*\.\s*history_measurement_lines\s*\(\s*\)')
        self.assertIn('transcript.admission_diagnostic_lines()',gate)
        self.assertIn('let _ = writeln!',gate)
        self.assertNotIn('outcome.is_ok()',gate)
        transcript=(self.base/'rolling_transcript_v1.rs').read_text()
        self.assertIn('pub(super) const MAX_BYTES: usize = 262_144;',transcript)
        self.assertRegex(transcript,r'self\.timing_retained_bytes\(\)\s*\+\s*self\.history_measurement_retained_bytes\(\)')
        self.assertEqual(transcript.split('pub(super) fn tail(',1)[0].count('self.history_measurements.discard_for_budget();'),3)

    def test_history_seven_pure_filters_are_exact_source_backed_and_non_ipc(self):
        cases=[(output.HISTORY_MEASUREMENT_TESTS,self.base/'safe_diagnostics_v1.rs'),
               (output.HISTORY_TRANSCRIPT_TESTS,self.base/'rolling_transcript_v1.rs')]
        names=[]
        for selected,path in cases:
            source=path.read_text()
            for name in selected:
                names.append(name)
                self.assertEqual(source.count('fn '+name.rsplit('::',1)[1]+'()'),1)
        self.assertEqual(len(names),7)
        self.assertEqual(len(set(names)),7)
        self.assertTrue(set(names).isdisjoint(row[0] for row in output.TESTS.values()))
        self.assertTrue(set(names).isdisjoint(output.PURE_TESTS+output.TIMING_HOST_TESTS))



class PublicAdmissionDiagnosticTests(unittest.TestCase):
    base=PublicHistoryMeasurementTests.base

    def records(self):
        source=(self.base/'safe_diagnostics_v1.rs').read_text()
        return [json.loads(re.search(r'const '+name+r'_TEST_JSON: &str = r#"(.*?)"#;',source,re.S).group(1))
                for name in ('ADMISSION_MEASUREMENT','SIGNER_ADMISSION','WITNESS_ADMISSION')]

    def line(self, slot, row):
        return output.ADMISSION_PREFIXES[slot]+json.dumps(row,separators=(',',':'))+']'

    @staticmethod
    def objects(row, path=()):
        yield path,row
        for key,value in row.items():
            if type(value) is dict:
                yield from PublicAdmissionDiagnosticTests.objects(value,path+(key,))

    @staticmethod
    def at(row,path):
        for key in path: row=row[key]
        return row

    def test_all_required_keys_unknown_types_and_duplicate_fields_at_every_scope(self):
        for slot,original in enumerate(self.records()):
            parser=output.ADMISSION_PARSERS[slot]
            self.assertEqual(parser(json.dumps(original)),original)
            for path,obj in self.objects(original):
                for field in obj:
                    changed=json.loads(json.dumps(original)); del self.at(changed,path)[field]
                    with self.assertRaises(ValueError): parser(json.dumps(changed))
                    changed=json.loads(json.dumps(original)); self.at(changed,path)[field]=['private']
                    with self.assertRaises(ValueError): parser(json.dumps(changed))
                changed=json.loads(json.dumps(original)); self.at(changed,path)['private']='payload'
                with self.assertRaises(ValueError): parser(json.dumps(changed))
                field=next(iter(obj)); text=json.dumps(original,separators=(',',':'))
                duplicate=text.replace('"'+field+'":','"'+field+'":null,"'+field+'":',1)
                with self.assertRaises(ValueError): parser(duplicate)
            for malformed in ([],None,True,'private'):
                with self.assertRaises(ValueError): parser(json.dumps(malformed))

    def test_every_scalar_refuses_boolean_float_negative_and_out_of_bounds(self):
        for slot,original in enumerate(self.records()):
            parser=output.ADMISSION_PARSERS[slot]
            for path,obj in self.objects(original):
                for key,value in obj.items():
                    if type(value) is int or (value is None and key.endswith('_us')):
                        maximum=1 if key in ('version','pre_budget_callback_calls') else 1000000 if key.endswith('_calls') or key=='calls' else 600000000
                        for bad in (True,False,-1,maximum+1,1.0,float('nan'),float('inf'),float('-inf'),'0',{},[]):
                            changed=json.loads(json.dumps(original)); self.at(changed,path)[key]=bad
                            with self.assertRaises(ValueError): parser(json.dumps(changed))
                    elif type(value) is bool:
                        for bad in (0,1,'false',[],{},None):
                            # Only the two explicit witness observations are nullable booleans.
                            if bad is None and key in ('snapshot_recorded','controlled_result'): continue
                            changed=json.loads(json.dumps(original)); self.at(changed,path)[key]=bad
                            with self.assertRaises(ValueError): parser(json.dumps(changed))

    def test_closed_enums_producers_and_wire_parser_sets_are_in_parity(self):
        source=(self.base/'safe_diagnostics_v1.rs').read_text()
        pairs=[('DurableAdmissionDispatchStageV1',output.SIGNER_ADMISSION_STAGES),
               ('DurableAdmissionCompletionV1',output.SIGNER_ADMISSION_COMPLETIONS),
               ('DurableAdmissionRetentionV1',output.SIGNER_ADMISSION_RETENTIONS),
               ('DurableAdmissionCallbackStageV1',output.SIGNER_ADMISSION_CALLBACK_STAGES),
               ('AdmissionWitnessStageV1',output.WITNESS_ADMISSION_STAGES),
               ('AdmissionWitnessAttributionV1',output.WITNESS_ADMISSION_ATTRIBUTIONS),
               ('AdmissionWitnessResultV1',output.WITNESS_ADMISSION_RESULTS),
               ('AdmissionWitnessCompletionV1',output.WITNESS_ADMISSION_COMPLETIONS),
               ('AdmissionWitnessCommitV1',output.WITNESS_ADMISSION_COMMITS),
               ('AdmissionWitnessReceiptGateV1',output.WITNESS_ADMISSION_RECEIPT_GATES),
               ('AdmissionWitnessCorrelationV1',output.WITNESS_ADMISSION_CORRELATIONS),
               ('CheckedHistoryIoKindV1',output.ADMISSION_IO_KINDS)]
        for name,values in pairs:
            actual=set(re.findall(name+r'::([A-Za-z0-9]+) => "([A-Za-z0-9]+)"',source))
            self.assertEqual(actual,{(value,value) for value in values})
        def body(name): return source.split('fn '+name+'(',1)[1].split('\n}\n',1)[0]
        for name,fields in [('admission_measurement_json',output.ADMISSION_MEASUREMENT_FIELDS),
                ('signer_admission_json',output.SIGNER_ADMISSION_FIELDS),
                ('signer_admission_measurement_json',output.SIGNER_ADMISSION_MEASUREMENT_FIELDS),
                ('witness_admission_error_json',output.WITNESS_ADMISSION_ERROR_FIELDS)]:
            self.assertEqual(set(re.findall(r'"([a-z_]+)":',body(name))),fields)
        witness=body('witness_admission_json')
        self.assertEqual(set(re.findall(r'"([a-z_]+)":',witness)),output.WITNESS_ADMISSION_FIELDS|output.WITNESS_ADMISSION_SPANS)
        spans=set(re.findall(r'"([a-z_]+)"\s*:\s*witness_admission_cost_json\s*\(\s*value\.cost\s*\(\s*AdmissionWitnessSpanV1::([A-Za-z]+)\s*\)\s*\)',witness))
        self.assertEqual({key for key,_ in spans},output.WITNESS_ADMISSION_SPANS)
        self.assertEqual({variant for _,variant in spans},{''.join(word.title() for word in key.split('_')) for key in output.WITNESS_ADMISSION_SPANS})
        self.assertEqual(set(re.findall(r'"([a-z_]+)":',body('witness_admission_cost_json'))),{'calls','elapsed_us'})
        self.assertIn('value.history_elapsed_us()',body('admission_measurement_json'))
        self.assertIn('value.history_cost()',body('admission_measurement_json'))
        for name in ('PublicAdmissionMeasurement','PublicSignerAdmission','PublicSignerAdmissionMeasurement','PublicWitnessAdmission','PublicWitnessAdmissionError','PublicWitnessAdmissionCost'):
            dto=source.split('struct '+name+' {',1)[1].split('\n}',1)[0]
            self.assertEqual(dto.count('#[serde(deserialize_with = "required_history_nullable")]'),len(re.findall(r'^    [a-z_]+: Option<',dto,re.M)))

    def test_every_closed_enum_accepts_exact_values_and_rejects_free_form(self):
        cases=[(0,(),[('phase',{'Admission'}),('check_site',output.ADMISSION_CHECK_SITES),('checkpoint',output.HISTORY_CHECKPOINTS),('selected_limit',output.HISTORY_SELECTED_LIMITS)]),
               (1,(),[('stage',output.SIGNER_ADMISSION_STAGES),('completion',output.SIGNER_ADMISSION_COMPLETIONS),('retention',output.SIGNER_ADMISSION_RETENTIONS),('original_error',output.SIGNER_ADMISSION_ERRORS),('callback_stage',output.SIGNER_ADMISSION_CALLBACK_STAGES)]),
               (2,(),[('worker_result',output.WITNESS_ADMISSION_RESULTS),('fixture_result',output.WITNESS_ADMISSION_RESULTS),('worker_error',output.ADMISSION_AUTHORITY_ERRORS),('fixture_error',output.ADMISSION_AUTHORITY_ERRORS),('worker_stage',output.WITNESS_ADMISSION_STAGES),('fixture_stage',output.WITNESS_ADMISSION_STAGES),('completion',output.WITNESS_ADMISSION_COMPLETIONS),('commit',output.WITNESS_ADMISSION_COMMITS),('receipt_gate',output.WITNESS_ADMISSION_RECEIPT_GATES),('final_correlation',output.WITNESS_ADMISSION_CORRELATIONS)])]
        for error in ('first_semantic','first_connection'):
            cases.append((2,(error,),[('stage',output.WITNESS_ADMISSION_STAGES),('attribution',output.WITNESS_ADMISSION_ATTRIBUTIONS),('io_kind',output.ADMISSION_IO_KINDS),('error',output.ADMISSION_AUTHORITY_ERRORS)]))
        for slot,path,fields in cases:
            for field,values in fields:
                for value in values:
                    row=self.records()[slot]; self.at(row,path)[field]=value
                    self.assertEqual(output.ADMISSION_PARSERS[slot](json.dumps(row)),row)
                for bad in ('private','',0,True,{},[]):
                    row=self.records()[slot]; self.at(row,path)[field]=bad
                    with self.assertRaises(ValueError): output.ADMISSION_PARSERS[slot](json.dumps(row))

    def test_null_is_unavailable_zero_is_measured_and_commit_is_never_inferred(self):
        rows=self.records()
        for field in output.HISTORY_OPTIONAL_DURATIONS|{'phase','check_site','selected_limit','exchange_cost'}: rows[0][field]=None
        for field in output.SIGNER_ADMISSION_DURATIONS|output.SIGNER_ADMISSION_COUNTS: rows[1]['measurement'][field]=None
        for field in ('first_semantic','first_connection','worker_error','fixture_error','worker_stage','fixture_stage','controlled_result','snapshot_recorded'): rows[2][field]=None
        for slot,row in enumerate(rows): self.assertEqual(output.ADMISSION_PARSERS[slot](json.dumps(row)),row)
        for slot,path,field in [(0,(),'selected_remaining_at_failure_us'),(1,('measurement',),'request_validation_us'),(2,('cost','commit'),'elapsed_us')]:
            row=rows[slot]; self.at(row,path)[field]=0
            self.assertEqual(output.ADMISSION_PARSERS[slot](json.dumps(row)),row)
        for commit in output.WITNESS_ADMISSION_COMMITS:
            row=rows[2]; row['commit']=commit
            parsed=output.public_witness_admission(json.dumps(row))
            self.assertEqual(parsed['commit'],commit)
            self.assertIsNone(parsed['snapshot_recorded'])
        rows[1]['measurement']=None; rows[1]['original_error']=None
        rows[1]['completion']='Missing'; rows[1]['retention']='Unconfirmed'
        self.assertEqual(output.public_signer_admission(json.dumps(rows[1])),rows[1])
        history=PublicHistoryMeasurementTests().record(); history['phase']='Admission'
        with self.assertRaises(ValueError): output.public_history_measurement(json.dumps(history))
        for phase in ('Snapshot','Page'):
            row=self.records()[0]; row['phase']=phase
            with self.assertRaises(ValueError): output.public_admission_measurement(json.dumps(row))
        for site in output.HISTORY_CHECK_SITES-output.ADMISSION_CHECK_SITES:
            row=self.records()[0]; row['check_site']=site
            with self.assertRaises(ValueError): output.public_admission_measurement(json.dumps(row))

    def test_all_slots_framing_split_lines_and_oversize_never_expose_private_text(self):
        for slot,row in enumerate(self.records()):
            raw=self.line(slot,row).encode(); kind=output.ADMISSION_KINDS[slot]
            for prefix in (b'',b'test fixed ... '):
                self.assertEqual(output.public_line(prefix+raw,'fixed'),(kind,row))
                self.assertEqual(output.public_line(prefix+output.ADMISSION_PREFIXES[slot].encode()+b'\xff]','fixed'),(kind+'_invalid',None))
            self.assertIsNone(output.public_line(b'private '+raw,'fixed'))
            for invalid in (raw+b' private',raw[:-1],raw+raw):
                self.assertEqual(output.public_line(invalid,'fixed'),(kind+'_invalid',None))
            framing=output.BoundedLines(); split=len(raw)//2
            self.assertEqual(framing.feed(raw[:split]),[])
            self.assertEqual(framing.feed(raw[split:]+b'\n'),[raw])
            self.assertEqual(framing.feed(b'x'*8193+raw[:split]),[])
            self.assertEqual(framing.feed(raw[split:]+b'\n'+raw+b'\n'),[raw])
            with self.assertRaises(ValueError): output.ADMISSION_PARSERS[slot](' '*4097)
            deep=output.ADMISSION_PREFIXES[slot]+'['*1500+'0'+']'*1500+']'
            self.assertEqual(output.public_line(deep.encode(),'fixed'),(kind+'_invalid',None))

    def test_new_slots_are_independent_sticky_and_do_not_overwrite(self):
        rows=self.records(); capture=output.AdmissionDiagnostics()
        for kind,row in zip(output.ADMISSION_KINDS,rows): capture.record(kind,row)
        capture.record('signer_admission',rows[1])
        capture.record('signer_admission',rows[1])
        self.assertEqual(capture.records,[rows[0],None,rows[2]])
        capture.record('witness_admission_invalid',None)
        capture.record('witness_admission',rows[2])
        saved=io.StringIO()
        with contextlib.redirect_stdout(saved): capture.emit()
        lines=saved.getvalue().splitlines()
        self.assertEqual(output.public_line(lines[0].encode(),'fixed'),('admission_measurement',rows[0]))
        self.assertEqual(lines[1:],list(output.ADMISSION_INVALID[1:]))
        for slot in (1,2): self.assertEqual(output.public_line(lines[slot].encode(),'fixed'),(output.ADMISSION_KINDS[slot]+'_invalid',None))
        with mock.patch('builtins.print',side_effect=OSError('private')): capture.emit()
        with contextlib.redirect_stdout(io.StringIO()), mock.patch.object(output.json,'dumps',side_effect=ValueError('private')): capture.emit()

    def test_cleanup_and_exact_phase_gates_preserve_original_outcome(self):
        lines=[self.line(slot,row) for slot,row in enumerate(self.records())]
        fake=PublicTimingTests().run_fake
        failed=fake(lines,phase='durable-fixed-signing')
        for prefix in output.ADMISSION_PREFIXES:
            self.assertIn(prefix,failed)
            self.assertLess(failed.index('[JOINED_CLEANUP '),failed.index(prefix))
            self.assertNotIn(prefix,fake(lines,verified=False,phase='durable-fixed-signing'))
            self.assertNotIn(prefix,fake(lines,status=0,cleanup_present=False,phase='durable-fixed-signing'))
        self.assertNotIn('passed=true',failed)
        for rows in ([],lines,[lines[1],lines[1]],['[WITNESS_ADMISSION_V1 {"private":"payload"}]']):
            success=fake(rows,status=0,phase='durable-fixed-signing')
            self.assertIn('phase=durable-fixed-signing passed=true cleanup_verified=true',success)
            self.assertNotIn('private',success); self.assertNotIn('payload',success)
        for phase in ('initial','full','durable-owner-reopen'):
            other=fake(lines,status=0,phase=phase)
            for prefix in output.ADMISSION_PREFIXES: self.assertNotIn(prefix,other)
        source=(ROOT/'scripts/ci-synthetic-output.py').read_text()
        gate=source.split('if phase in DURABLE_DIAGNOSTIC_PHASES and cleanup_observed:',1)[1].split("if phase=='full'",1)[0]
        self.assertIn('admission_diagnostics.emit()',gate)
        self.assertIn('if total > 16*1024*1024:',source)
        transcript=(self.base/'rolling_transcript_v1.rs').read_text()
        self.assertIn('pub(super) const MAX_BYTES: usize = 262_144;',transcript)
        self.assertEqual(transcript.split('pub(super) fn tail(',1)[0].count('self.admission_diagnostics.discard_for_budget();'),3)
        parent=self.base.with_suffix('.rs').read_text()
        gate=parent.split('if (stage == "durable-proposal-native-fixed-signing-v1"',1)[1].split('\n    if outcome.is_err()',1)[0]
        self.assertIn('&& process.verified()',gate)
        self.assertIn('&& root_cleanup == TemporaryRootCleanupV1::ClosedAndAbsenceVerified',gate)
        self.assertIn('transcript.admission_diagnostic_lines()',gate)
        self.assertNotIn('outcome.is_ok()',gate)

    def test_bounded_maximal_records_and_exact_pure_selectors(self):
        for slot,row in enumerate(self.records()):
            for path,obj in self.objects(row):
                for field,value in list(obj.items()):
                    if field=='version': continue
                    if field=='pre_budget_callback_calls': obj[field]=1
                    elif type(value) is int or (value is None and field.endswith('_us')):
                        obj[field]=1000000 if field.endswith('_calls') or field=='calls' else 600000000
            self.assertLessEqual(len(json.dumps(row,separators=(',',':')).encode()),4096)
            self.assertEqual(output.ADMISSION_PARSERS[slot](json.dumps(row)),row)
        cases=[(output.ADMISSION_PROJECTION_TESTS,self.base/'safe_diagnostics_v1.rs'),
               (output.ADMISSION_TRANSCRIPT_TESTS,self.base/'rolling_transcript_v1.rs'),
               (output.ADMISSION_HOST_TESTS,self.base/'durable_proposal_v1/worker.rs')]
        names=[]
        for selected,path in cases:
            source=path.read_text()
            for name in selected:
                names.append(name)
                self.assertEqual(source.count('fn '+name.rsplit('::',1)[1]+'()'),1)
        self.assertEqual(len(names),8); self.assertEqual(len(set(names)),8)
        self.assertTrue(set(names).isdisjoint(row[0] for row in output.TESTS.values()))


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


class PublicDurableFlowTests(unittest.TestCase):
    base=ROOT/'crates/wholepact-native-host/src/host/manual_enrollment/command/roster_publication_v2/sequential_construction_v3_qualification'
    # Exact shared literal from the reviewed maximal fixture, not an operational history.
    maximal='{"version":1,"operation":"WriterReconcile","first_error":{"stage":"AuthorizationSource","domain":"Signer","code":"ConsentJournal","nested_code":"JournalNamedRecipientHistoryUnsupported"},"terminal_error":{"stage":"AuthorizationSource","domain":"Signer","code":"ConsentJournal","nested_code":"JournalNamedRecipientHistoryUnsupported"},"fixture_result":"ReturnedErr","completion":{"purpose":"ActivationPrepare","result":"NotObserved","receive":"Disconnected","presentation":"NotObserved"},"call_outcomes":{"writer_acquire":"ReturnedErr","writer_activate":"ReturnedErr","active_verify":"ReturnedErr","reconciliation":"ReturnedErr","session_invalidation":"ReturnedErr","release":"ReturnedErr","request_retention":"ReturnedErr","reservation":"ReturnedErr","permit_retention":"ReturnedErr","key_use":"ReturnedErr","result_retention":"ReturnedErr"},"lower_call_measurement":{"purpose":"Activate","stage":"CommittedHeadValidation","authority_code":"ConstructionHistoryUnsupported","io_kind":"Timeout","callback_stage":"WorkspaceCurrent","measurement":{"phase":"Activate","check_site":"BeforeRequestWrite","checkpoint":"DeadlineSelection","selected_limit":"Exchange","selected_budget_us":600000000,"caller_remaining_at_budget_start_us":600000000,"caller_remaining_at_failure_us":600000000,"selected_remaining_at_failure_us":600000000,"operation_elapsed_us":600000000,"exchange_elapsed_us":600000000,"pre_budget_callback_calls":1,"pre_budget_callback_us":600000000,"operation_cost":{"callback_calls":1000000,"callback_us":600000000,"callback_max_us":600000000,"connect_calls":1000000,"connect_us":600000000,"handshake_calls":1000000,"handshake_us":600000000,"frame_write_calls":1000000,"frame_write_us":600000000,"frame_read_calls":1000000,"frame_read_us":600000000},"exchange_cost":{"callback_calls":1000000,"callback_us":600000000,"callback_max_us":600000000,"connect_calls":1000000,"connect_us":600000000,"handshake_calls":1000000,"handshake_us":600000000,"frame_write_calls":1000000,"frame_write_us":600000000,"frame_read_calls":1000000,"frame_read_us":600000000},"clamped":false,"incomplete":false}},"clamped":false,"incomplete":false,"after_drain":{"drain_result":"ReturnedErr","drain_error":{"stage":"Close","domain":"Signer","code":"ConsentJournal","nested_code":"JournalNamedRecipientHistoryUnsupported"},"worker_purpose":"ActivationPrepare","worker_result":"ReturnedErr","worker_error":{"stage":"AuthorizationSource","domain":"Signer","code":"ConsentJournal","nested_code":"JournalNamedRecipientHistoryUnsupported"},"call_outcomes":{"writer_acquire":"ReturnedErr","writer_activate":"ReturnedErr","active_verify":"ReturnedErr","reconciliation":"ReturnedErr","session_invalidation":"ReturnedErr","release":"ReturnedErr","request_retention":"ReturnedErr","reservation":"ReturnedErr","permit_retention":"ReturnedErr","key_use":"ReturnedErr","result_retention":"ReturnedErr"},"lower_call_measurement":null,"clamped":false,"incomplete":false}}'

    def record(self): return json.loads(self.maximal)
    def line(self,row=None): return output.FLOW_PREFIX+json.dumps(self.record() if row is None else row,separators=(',',':'))
    def objects(self,row,path=()):
        if type(row) is dict:
            yield path,row
            for key,value in row.items(): yield from self.objects(value,path+(key,))
    def at(self,row,path):
        for key in path: row=row[key]
        return row
    def valid(self,row): return output.public_durable_flow(json.dumps(row,separators=(',',':')))

    def test_exact_maximal_production_canonical_parity_and_cap(self):
        row=output.public_durable_flow(self.maximal)
        self.assertEqual(len(self.maximal.encode('utf8')),2937)
        self.assertEqual(hashlib.sha256(self.maximal.encode()).hexdigest(),'4b232233f3895e69771e0a113a442d0687779d29e08f9772504da9b99f20c5bb')
        self.assertEqual(json.dumps(row,separators=(',',':')),self.maximal)
        escaped=self.maximal.replace('WriterReconcile','\\u0057riterReconcile',1)
        self.assertEqual(json.dumps(output.public_durable_flow(escaped),separators=(',',':')),self.maximal)
        source=(self.base/'safe_diagnostics_v1.rs').read_text()
        golden=re.search(r'const DURABLE_FLOW_MAXIMAL_TEST_JSON: &str = r#"([^\n]+)"#;',source).group(1)
        self.assertEqual(golden,self.maximal)
        exact=self.maximal+' '*(4096-len(self.maximal.encode('utf8')))
        self.assertEqual(output.public_durable_flow(exact),row)
        with self.assertRaises(ValueError): output.public_durable_flow(exact+' ')
        # Every object order is normalized, not forwarded from input formatting.
        def reverse(value):
            return {key:reverse(child) for key,child in reversed(list(value.items()))} if type(value) is dict else value
        self.assertEqual(json.dumps(self.valid(reverse(row)),separators=(',',':')),self.maximal)
        capture=output.DurableFlowDiagnostics(); capture.record('durable_flow',row)
        saved=io.StringIO()
        with contextlib.redirect_stdout(saved): capture.emit()
        self.assertEqual(saved.getvalue(),output.FLOW_PREFIX+self.maximal+'\n')

    def test_all_scopes_require_every_key_and_reject_duplicate_escaped_or_extra_keys(self):
        original=self.record(); text=json.dumps(original,separators=(',',':'))
        for path,obj in self.objects(original):
            fragment=json.dumps(obj,separators=(',',':'))
            row=self.record(); self.at(row,path)['private']='path/token/payload'
            with self.assertRaises(ValueError): self.valid(row)
            for key,value in obj.items():
                row=self.record(); del self.at(row,path)[key]
                with self.assertRaises(ValueError): self.valid(row)
                for spelling in (key,'\\u%04x'%ord(key[0])+key[1:]):
                    duplicate='{'+json.dumps(spelling).replace('\\\\u','\\u')+':'+json.dumps(value,separators=(',',':'))+','+fragment[1:]
                    changed=text.replace(fragment,duplicate,1)
                    with self.assertRaises(ValueError): output.public_durable_flow(changed)
        for bad in (None,[],True,0,'private'):
            with self.assertRaises(ValueError): output.public_durable_flow(json.dumps(bad))
        for token in ('1.0','1e0','NaN','Infinity','-Infinity'):
            with self.assertRaises(ValueError): output.public_durable_flow(self.maximal.replace('"version":1','"version":'+token,1))

    def test_numbers_booleans_required_nulls_and_objects_are_strict(self):
        original=self.record()
        nullable={('after_drain',),('after_drain','lower_call_measurement'),('after_drain','drain_error','nested_code'),('after_drain','worker_error','nested_code'),('first_error',),('terminal_error',),('lower_call_measurement',),
            ('first_error','nested_code'),('terminal_error','nested_code'),('completion','purpose'),
            ('lower_call_measurement','io_kind'),('lower_call_measurement','callback_stage')}
        nullable|={('lower_call_measurement','measurement',key) for key in output.HISTORY_OPTIONAL_DURATIONS|{'phase','check_site','selected_limit','exchange_cost'}}
        for path,obj in self.objects(original):
            for key,value in obj.items():
                full=path+(key,)
                if type(value) is int:
                    bound=1 if key in ('version','pre_budget_callback_calls') else 1000000 if key.endswith('_calls') else 600000000
                    bads=(True,False,-1,bound+1,1.0,float('nan'),float('inf'),'0',{},[])
                elif type(value) is bool: bads=(None,0,1,'false',{},[])
                elif type(value) is str: bads=('private/path/token','',True,0,{},[])
                elif type(value) is dict: bads=(True,0,'private',[])
                else: bads=()
                for bad in bads:
                    row=self.record(); self.at(row,path)[key]=bad
                    with self.assertRaises(ValueError): self.valid(row)
                if full not in nullable:
                    row=self.record(); self.at(row,path)[key]=None
                    with self.assertRaises(ValueError): self.valid(row)
        row=self.record(); row['after_drain']=None; row['first_error']=None; row['terminal_error']=None; row['lower_call_measurement']=None
        row['completion']=dict(purpose=None,result='NotObserved',receive='NotObserved',presentation='NotObserved')
        self.assertEqual(self.valid(row),row)
        row=self.record()
        for field in output.HISTORY_OPTIONAL_DURATIONS|{'phase','check_site','selected_limit','exchange_cost'}:
            row['lower_call_measurement']['measurement'][field]=None
        row['lower_call_measurement']['measurement']['operation_elapsed_us']=0
        self.assertEqual(self.valid(row),row)

    def test_every_domain_code_and_immediate_nested_combination_is_closed(self):
        longest=0
        nested=set().union(*output.FLOW_NESTED_CODES.values())
        for domain,codes in output.FLOW_DOMAIN_CODES.items():
            for code in codes:
                permitted=output.FLOW_NESTED_CODES.get((domain,code),())
                for inner in (None,*nested):
                    error=dict(stage='AuthorizationSource',domain=domain,code=code,nested_code=inner)
                    row=self.record(); row['first_error']=error
                    if inner is None or inner in permitted:
                        self.assertEqual(self.valid(row),row)
                        longest=max(longest,len(json.dumps(error,separators=(',',':')).encode('utf8')))
                    else:
                        with self.assertRaises(ValueError): self.valid(row)
        self.assertEqual(longest,129)
        for domain,code in [('Wallet','Storage'),('Signer','SessionRequired'),('Bridge','Database'),('Authority','Io')]:
            row=self.record(); row['first_error'].update(domain=domain,code=code,nested_code=None)
            with self.assertRaises(ValueError): self.valid(row)

    def test_every_enum_and_lower_purpose_uses_exact_finite_inventory(self):
        cases=[((), 'operation',output.FLOW_OPERATION),
            (('first_error',),'stage',output.FLOW_STAGE),
            (('lower_call_measurement',),'stage',output.FLOW_TRANSPORT_STAGE),
            (('lower_call_measurement',),'authority_code',output.FLOW_AUTHORITY_CODE),
            (('lower_call_measurement',),'io_kind',output.ADMISSION_IO_KINDS),
            (('lower_call_measurement',),'callback_stage',output.FLOW_CALLBACK_STAGE),
            (('lower_call_measurement','measurement'),'check_site',output.ADMISSION_CHECK_SITES),
            (('lower_call_measurement','measurement'),'checkpoint',output.HISTORY_CHECKPOINTS),
            (('lower_call_measurement','measurement'),'selected_limit',output.HISTORY_SELECTED_LIMITS)]
        cases += [(('call_outcomes',),key,output.FLOW_CALL_OUTCOME) for key in output.FLOW_CALL_FIELDS]
        for path,field,values in cases:
            for value in values:
                row=self.record(); row['after_drain']=None; self.at(row,path)[field]=value
                self.assertEqual(self.valid(row),row)
        for purpose in output.FLOW_TRANSPORT_PURPOSE:
            row=self.record(); lower=row['lower_call_measurement']; lower['purpose']=purpose; lower['measurement']['phase']=purpose
            if purpose=='Reserve':
                lower['measurement']['caller_remaining_at_budget_start_us']=None
                lower['measurement']['caller_remaining_at_failure_us']=None
            self.assertEqual(self.valid(row),row)
            lower['measurement']['phase']=None; self.assertEqual(self.valid(row),row)
            for phase in output.FLOW_TRANSPORT_PURPOSE- {purpose} | {'Snapshot','Page','Admission'}:
                lower['measurement']['phase']=phase
                with self.assertRaises(ValueError): self.valid(row)
        for phase in output.FLOW_TRANSPORT_PURPOSE:
            for old in (PublicHistoryMeasurementTests().record(),PublicAdmissionDiagnosticTests().records()[0]):
                old['phase']=phase
                parser=output.public_history_measurement if 'history_cost' in old else output.public_admission_measurement
                with self.assertRaises(ValueError): parser(json.dumps(old))

    def test_completion_truth_table_and_measurement_flags_preserve_uncertainty(self):
        for purpose in (None,*output.FLOW_JOB_PURPOSE):
            for result in output.FLOW_RESULT:
                for receive in output.FLOW_RECEIVE:
                    for presentation in output.FLOW_PRESENTATION:
                        valid=(purpose is not None or (result=='NotObserved' and presentation=='NotObserved' and receive in ('NotObserved','Missing')))
                        valid &= receive!='Received' or (purpose is not None and result in ('ReturnedOk','ReturnedErr'))
                        valid &= receive not in ('Pending','Disconnected') or (result=='NotObserved' and presentation=='NotObserved')
                        valid &= presentation!='Accepted' or (receive=='Received' and result=='ReturnedOk')
                        valid &= presentation!='Suppressed' or receive in ('Received','Invalidated')
                        row=self.record(); row['after_drain']=None; row['completion']=dict(purpose=purpose,result=result,receive=receive,presentation=presentation)
                        if valid: self.assertEqual(self.valid(row),row)
                        else:
                            with self.assertRaises(ValueError): self.valid(row)
        for flag in ('clamped','incomplete'):
            row=self.record(); row['lower_call_measurement']['measurement'][flag]=True
            with self.assertRaises(ValueError): self.valid(row)
            row[flag]=True; self.assertEqual(self.valid(row),row)
        row=self.record(); lower=row['lower_call_measurement']; lower['purpose']='Reserve'; lower['measurement']['phase']='Reserve'
        with self.assertRaises(ValueError): self.valid(row)
        lower['measurement']['caller_remaining_at_budget_start_us']=None; lower['measurement']['caller_remaining_at_failure_us']=None
        self.assertEqual(self.valid(row),row)
        lower['measurement']['selected_limit']='Caller'
        with self.assertRaises(ValueError): self.valid(row)
        for result in ('ReturnedOk','NotObserved',None):
            row=self.record(); row['fixture_result']=result
            with self.assertRaises(ValueError): self.valid(row)

    def test_after_drain_distinguishes_worker_return_from_receive_and_initial_error(self):
        row=self.record(); after=row['after_drain']
        row['completion'].update(purpose='Acquire',result='NotObserved',receive='Pending',presentation='NotObserved')
        after.update(worker_purpose='Acquire',worker_result='ReturnedOk',worker_error=None,drain_result='ReturnedOk',drain_error=None)
        row['call_outcomes']['writer_acquire']='Entered'
        after['call_outcomes']['writer_acquire']='ReturnedOk'
        original=json.loads(json.dumps({key:value for key,value in row.items() if key!='after_drain'}))
        self.assertEqual(self.valid(row),row)
        self.assertEqual({key:value for key,value in row.items() if key!='after_drain'},original)
        self.assertEqual(row['completion']['receive'],'Pending')
        self.assertEqual(row['completion']['presentation'],'NotObserved')
        for key,bad in [('drain_result','NotObserved'),('drain_error',row['first_error']),
                ('worker_purpose','Activate'),('worker_error',row['first_error'])]:
            changed=json.loads(json.dumps(row)); changed['after_drain'][key]=bad
            with self.assertRaises(ValueError): self.valid(changed)
        row['completion'].update(result='ReturnedErr',receive='Received',presentation='Suppressed')
        with self.assertRaises(ValueError): self.valid(row)
        row['after_drain']=None
        self.assertEqual(self.valid(row),row)

    def test_after_drain_final_calls_never_regress_or_duplicate_first_lower(self):
        for old in output.FLOW_CALL_OUTCOME:
            for new in output.FLOW_CALL_OUTCOME:
                row=self.record(); row['call_outcomes']['writer_acquire']=old
                row['after_drain']['call_outcomes']['writer_acquire']=new
                expected=not ((old in ('ReturnedOk','ReturnedErr') and new!=old) or (old=='Entered' and new=='NotObserved'))
                if expected: self.assertEqual(self.valid(row),row)
                else:
                    with self.assertRaises(ValueError): self.valid(row)
        row=self.record(); row['after_drain']['lower_call_measurement']=row['lower_call_measurement']
        with self.assertRaises(ValueError): self.valid(row)
        row['lower_call_measurement']=None
        self.assertEqual(self.valid(row),row)
        for flag in ('clamped','incomplete'):
            row['after_drain']['lower_call_measurement']['measurement'][flag]=True
            with self.assertRaises(ValueError): self.valid(row)
            row['after_drain'][flag]=True; self.assertEqual(self.valid(row),row)
        row=self.record(); row['completion']['purpose']=None
        row['completion']['receive']='Missing'
        row['after_drain'].update(worker_purpose=None,worker_result='NotObserved',worker_error=None)
        self.assertEqual(self.valid(row),row)
        row['after_drain']['worker_result']='ReturnedOk'
        with self.assertRaises(ValueError): self.valid(row)

    def test_singleton_malformed_duplicate_oversized_and_output_loss_are_optional(self):
        row=self.record(); raw=self.line().encode()
        self.assertEqual(output.public_line(raw,'fixed'),('durable_flow',row))
        self.assertEqual(output.public_line(b'test fixed ... '+raw,'fixed'),('durable_flow',row))
        self.assertIsNone(output.public_line(b'private '+raw,'fixed'))
        self.assertIsNone(output.public_line((output.FLOW_PRIVATE_PREFIX+self.maximal+']').encode(),'fixed'))
        invalid=(output.FLOW_PREFIX+'{"private":"path/token/secret"}').encode()
        for candidate in (invalid,raw+b' private',raw+raw,output.FLOW_PREFIX.encode()+b'\xff',b'CI_SYNTHETIC_DURABLE_FLOW{}'):
            self.assertEqual(output.public_line(candidate,'fixed'),('durable_flow_invalid',None))
        for sequence in ([('durable_flow',row)]*2,[('durable_flow_invalid',None),('durable_flow',row)],
                         [('durable_flow',row),('durable_flow_invalid',None)]):
            capture=output.DurableFlowDiagnostics()
            for kind,value in sequence: capture.record(kind,value)
            saved=io.StringIO()
            with contextlib.redirect_stdout(saved): capture.emit()
            self.assertEqual(saved.getvalue(),output.FLOW_INVALID+'\n')
        for prefix in (b'',b'test fixed ... '):
            oversized=prefix+output.FLOW_PREFIX.encode()+b'x'*9000
            self.assertEqual(output.public_line(oversized,'fixed'),('durable_flow_invalid',None))
            framing=output.BoundedLines('fixed'); lines=[]
            for at in range(0,len(oversized),111): lines.extend(framing.feed(oversized[at:at+111]))
            lines.extend(framing.feed(b'\n'))
            self.assertEqual(lines,[output.FLOW_INVALID.encode()]); self.assertLessEqual(len(framing.pending),8192)
        framing=output.BoundedLines('fixed'); cut=len(raw)//2
        self.assertEqual(framing.feed(raw[:cut]),[]); self.assertEqual(framing.feed(raw[cut:]+b'\n'),[raw])
        capture=output.DurableFlowDiagnostics(); capture.record('durable_flow',row)
        with mock.patch('builtins.print',side_effect=OSError('private')): capture.emit()
        with mock.patch.object(output.json,'dumps',side_effect=ValueError('private')): capture.emit()

    def test_exact_phase_verified_cleanup_and_original_outcome_gates(self):
        fake=PublicTimingTests().run_fake; line=self.line()
        failed=fake([line],phase='durable-fixed-signing')
        self.assertIn(output.FLOW_PREFIX,failed); self.assertNotIn('passed=true',failed)
        self.assertLess(failed.index('[JOINED_CLEANUP '),failed.index(output.FLOW_PREFIX))
        for kwargs in (dict(verified=False),dict(cleanup_present=False)):
            self.assertNotIn(output.FLOW_PREFIX,fake([line],phase='durable-fixed-signing',**kwargs))
        for phase in ('initial','full','durable-owner-reopen'):
            self.assertNotIn(output.FLOW_PREFIX,fake([line],phase=phase,status=0))
        for lines in ([],[line],[line,line],[output.FLOW_PREFIX+'{"private":"payload"}']):
            result=fake(lines,phase='durable-fixed-signing',status=0)
            self.assertIn('phase=durable-fixed-signing passed=true cleanup_verified=true',result)
            self.assertNotIn('private',result); self.assertNotIn('payload',result)
        parent=self.base.with_suffix('.rs').read_text()
        gate=parent.split('if (stage == "durable-proposal-native-fixed-signing-v1"',1)[1].split('\n    if outcome.is_err()',1)[0]
        self.assertIn('&& process.verified()',gate); self.assertIn('&& root_cleanup == TemporaryRootCleanupV1::ClosedAndAbsenceVerified',gate)
        self.assertIn('transcript.durable_flow_lines()',gate); self.assertNotIn('outcome.is_ok()',gate)
        source=(ROOT/'scripts/ci-synthetic-output.py').read_text(); gate=source.split('if phase in DURABLE_DIAGNOSTIC_PHASES and cleanup_observed:',1)[1].split("if phase=='full'",1)[0]
        self.assertIn('durable_flow.emit()',gate); self.assertIn('if total > 16*1024*1024:',source)
        rolling=(self.base/'rolling_transcript_v1.rs').read_text()
        self.assertIn('pub(super) const MAX_BYTES: usize = 262_144;',rolling)
        self.assertEqual(rolling.split('pub(super) fn tail(',1)[0].count('self.durable_flow.discard_for_budget();'),3)

    def test_production_getter_inventory_and_exact_non_native_selectors(self):
        source=(self.base/'safe_diagnostics_v1.rs').read_text()
        for typename,values in [('Operation',output.FLOW_OPERATION),('Stage',output.FLOW_STAGE),
                ('ErrorDomain',output.FLOW_ERROR_DOMAIN),('JobPurpose',output.FLOW_JOB_PURPOSE),
                ('Result',output.FLOW_RESULT),('Receive',output.FLOW_RECEIVE),('Presentation',output.FLOW_PRESENTATION),
                ('CallOutcome',output.FLOW_CALL_OUTCOME),('TransportPurpose',output.FLOW_TRANSPORT_PURPOSE),
                ('TransportStage',output.FLOW_TRANSPORT_STAGE),('AuthorityCode',output.FLOW_AUTHORITY_CODE),
                ('CallbackStage',output.FLOW_CALLBACK_STAGE)]:
            body=re.search(r'flow_labels!\s*\([^;]*?DurableFlow'+typename+r'V1,\s*\{(.*?)\}\s*\);',source,re.S).group(1)
            self.assertEqual(set(re.findall(r'([A-Za-z]+)\s*=>\s*"([A-Za-z]+)"',body)),{(value,value) for value in values})
        for typename,expected in [
                ('ErrorCode',{(domain+code,code) for domain,codes in output.FLOW_DOMAIN_CODES.items() for code in codes}),
                ('NestedCode',{(code,code) for codes in output.FLOW_NESTED_CODES.values() for code in codes})]:
            body=re.search(r'flow_labels!\s*\([^;]*?DurableFlow'+typename+r'V1,\s*\{(.*?)\}\s*\);',source,re.S).group(1)
            self.assertEqual(set(re.findall(r'([A-Za-z]+)\s*=>\s*"([A-Za-z]+)"',body)),expected)
        for names,file in [(output.FLOW_PROJECTION_TESTS,self.base/'safe_diagnostics_v1.rs'),
                (output.FLOW_TRANSCRIPT_TESTS,self.base/'rolling_transcript_v1.rs'),
                (output.FLOW_HOST_TESTS,self.base/'durable_proposal_v1/worker.rs')]:
            text=file.read_text()
            for name in names:
                self.assertEqual(len(re.findall(r'fn '+name.rsplit('::',1)[1]+r'\(',text)),1)
        self.assertEqual(len(output.FLOW_PROJECTION_TESTS)+len(output.FLOW_TRANSCRIPT_TESTS)+len(output.FLOW_HOST_TESTS),21)
        for struct,fields in [('PublicDurableFlow',output.FLOW_FIELDS),('PublicFlowError',output.FLOW_ERROR_FIELDS),
                ('PublicFlowCompletion',output.FLOW_COMPLETION_FIELDS),('PublicFlowCallOutcomes',output.FLOW_CALL_FIELDS),
                ('PublicFlowMeasurement',output.FLOW_MEASUREMENT_FIELDS),('PublicFlowLowerCall',output.FLOW_LOWER_FIELDS),
                ('PublicFlowAfterDrain',output.FLOW_AFTER_FIELDS),('PublicDurableLifecycle',output.LIFECYCLE_FIELDS)]:
            body=source.split('struct '+struct+' {',1)[1].split('\n    }',1)[0]
            self.assertEqual(tuple(re.findall(r'^\s+([a-z_]+):',body,re.M)),fields)
            self.assertEqual(body.count('#[serde(deserialize_with = "required_history_nullable")]'),len(re.findall(r'^\s+[a-z_]+: Option<',body,re.M)))

class PublicDurableLifecycleTests(unittest.TestCase):
    maximal='{"version":1,"operation":"WriterReconcile","fixture_result":"ReturnedErr","owner_budget_us":120000000,"points":{"native_open_complete":{"age_us":100000000,"remaining_us":20000000},"pair_complete":{"age_us":100000000,"remaining_us":20000000},"witness_setup_complete":{"age_us":100000000,"remaining_us":20000000},"accept_complete":{"age_us":100000000,"remaining_us":20000000},"redisclosure_complete":{"age_us":100000000,"remaining_us":20000000},"import_complete":{"age_us":100000000,"remaining_us":20000000},"historical_lookup_complete":{"age_us":100000000,"remaining_us":20000000},"acquire_prepare_launch":{"age_us":100000000,"remaining_us":20000000},"acquire_prepare_complete":{"age_us":100000000,"remaining_us":20000000},"acquire_native_approval":{"age_us":100000000,"remaining_us":20000000},"acquire_worker_launch":{"age_us":100000000,"remaining_us":20000000},"writer_reconcile_complete":{"age_us":100000000,"remaining_us":20000000},"post_reconcile_accept_complete":{"age_us":100000000,"remaining_us":20000000},"viewing_setup_complete":{"age_us":100000000,"remaining_us":20000000},"post_reconcile_redisclosure_native_complete":{"age_us":100000000,"remaining_us":20000000},"financial_import_poll_start":{"age_us":100000000,"remaining_us":20000000},"financial_import_complete":{"age_us":100000000,"remaining_us":20000000},"initial_sign_complete":{"age_us":100000000,"remaining_us":20000000},"fixture_failure":{"age_us":100000000,"remaining_us":20000000},"after_drain":{"age_us":100000000,"remaining_us":20000000}},"pending_wait":{"full_precheck":{"calls":1000000,"total_us":600000000,"max_us":600000000},"full_postcheck":{"calls":1000000,"total_us":600000000,"max_us":600000000},"liveness":{"calls":1000000,"total_us":600000000,"max_us":600000000},"poll":{"calls":1000000,"total_us":600000000,"max_us":600000000}},"worker_purpose":"ActivationPrepare","worker_started_to_client_entry_us":600000000,"worker_started_to_client_return_us":600000000,"clamped":false,"incomplete":false}'
    base=PublicDurableFlowTests.base
    objects=PublicDurableFlowTests.objects
    at=PublicDurableFlowTests.at
    def record(self): return json.loads(self.maximal)
    def valid(self,row): return output.public_durable_lifecycle(json.dumps(row,separators=(',',':')))
    def line(self,row=None): return output.LIFECYCLE_PREFIX+json.dumps(self.record() if row is None else row,separators=(',',':'))

    def test_maximal_canonical_parity_caps_and_pairing(self):
        row=self.valid(self.record())
        self.assertEqual(len(self.maximal.encode()),1979)
        self.assertEqual(hashlib.sha256(self.maximal.encode()).hexdigest(),'69414cc5082857eb6773c0dff55718d92fe01f4352092b661cf45bdf34f0be2a')
        self.assertEqual(json.dumps(row,separators=(',',':')),self.maximal)
        source=(self.base/'safe_diagnostics_v1.rs').read_text()
        golden=re.search(r'const DURABLE_LIFECYCLE_MAXIMAL_TEST_JSON: &str = r#"([^\n]+)"#;',source).group(1)
        self.assertEqual(golden,self.maximal)
        exact=self.maximal+' '*(2048-len(self.maximal))
        self.assertEqual(output.public_durable_lifecycle(exact),row)
        with self.assertRaises(ValueError): output.public_durable_lifecycle(exact+' ')
        flow=output.DurableFlowDiagnostics(); flow.record('durable_flow',PublicDurableFlowTests().record())
        capture=output.DurableLifecycleDiagnostics(); capture.record('durable_lifecycle',row)
        saved=io.StringIO()
        with contextlib.redirect_stdout(saved): capture.emit(flow)
        self.assertEqual(saved.getvalue(),self.line()+'\n')
        for mismatch in ('operation','purpose','after_drain','absent','duplicate'):
            flow=output.DurableFlowDiagnostics(); value=PublicDurableFlowTests().record()
            if mismatch=='operation': value['operation']='InitialSign'
            if mismatch=='purpose':
                value['completion']['purpose']='Acquire'; value['after_drain']['worker_purpose']='Acquire'
            if mismatch=='after_drain': value['after_drain']=None
            if mismatch!='absent': flow.record('durable_flow',value)
            if mismatch=='duplicate': flow.record('durable_flow',value)
            saved=io.StringIO()
            with contextlib.redirect_stdout(saved): capture.emit(flow)
            self.assertEqual(saved.getvalue(),output.LIFECYCLE_INVALID+'\n')

        # Later sealed failure snapshots keep earlier owner points, not writer
        # worker timings or an invented drain/receive/result observation.
        for operation,purpose in (('FinancialImport','Import'),('InitialSign','Sign'),('RetainedRetry',None),('ResultService','ResultService')):
            row=self.record(); row.update(operation=operation,worker_purpose=purpose,
                worker_started_to_client_entry_us=None,worker_started_to_client_return_us=None)
            row['points']['after_drain']=None
            source_flow=PublicDurableFlowTests().record()
            source_flow.update(operation=operation,after_drain=None,lower_call_measurement=None)
            source_flow['completion']=dict(purpose=purpose,result='NotObserved',receive='Pending' if purpose else 'Missing',presentation='NotObserved')
            original=json.loads(json.dumps(source_flow))
            flow=output.DurableFlowDiagnostics(); flow.record('durable_flow',source_flow)
            capture=output.DurableLifecycleDiagnostics(); capture.record('durable_lifecycle',row)
            saved=io.StringIO()
            with contextlib.redirect_stdout(saved): capture.emit(flow)
            self.assertEqual(saved.getvalue(),self.line(row)+'\n')
            self.assertEqual(source_flow,original)
            self.assertIsNotNone(row['points']['native_open_complete'])
            self.assertIsNotNone(row['points']['writer_reconcile_complete'])
            self.assertEqual(self.valid(row),row)
            for key in ('worker_started_to_client_entry_us','worker_started_to_client_return_us'):
                changed=json.loads(json.dumps(row)); changed[key]=0
                with self.assertRaises(ValueError): self.valid(changed)
            changed=json.loads(json.dumps(row)); changed['points']['after_drain']=dict(age_us=120000000,remaining_us=0)
            with self.assertRaises(ValueError): self.valid(changed)
            source_flow['after_drain']=PublicDurableFlowTests().record()['after_drain']
            self.assertFalse(output.lifecycle_matches_flow(row,source_flow))

    def test_every_scope_nullable_and_duplicate_rules(self):
        original=self.record(); text=self.maximal
        for path,obj in self.objects(original):
            fragment=json.dumps(obj,separators=(',',':'))
            changed=self.record(); self.at(changed,path)['private']='path/token'
            with self.assertRaises(ValueError): self.valid(changed)
            for key,value in obj.items():
                changed=self.record(); del self.at(changed,path)[key]
                with self.assertRaises(ValueError): self.valid(changed)
                for spelling in (key,'\\u%04x'%ord(key[0])+key[1:]):
                    duplicate='{'+json.dumps(spelling).replace('\\\\u','\\u')+':'+json.dumps(value,separators=(',',':'))+','+fragment[1:]
                    with self.assertRaises(ValueError): output.public_durable_lifecycle(text.replace(fragment,duplicate,1))
                for bad in ([],{},'private/path',True,-1,1.0):
                    changed=self.record(); self.at(changed,path)[key]=bad
                    # True is a valid value only in the actual boolean flag slots.
                    if type(value) is bool and bad is True: continue
                    with self.assertRaises(ValueError): self.valid(changed)
        row=self.record()
        row['points']={key:None for key in output.LIFECYCLE_POINT_FIELDS}
        row.update(worker_purpose=None,worker_started_to_client_entry_us=None,worker_started_to_client_return_us=None)
        self.assertEqual(self.valid(row),row)
        for key in output.LIFECYCLE_POINT_FIELDS:
            changed=json.loads(json.dumps(row)); del changed['points'][key]
            with self.assertRaises(ValueError): self.valid(changed)

    def test_deadline_cost_and_worker_scalar_arithmetic_is_strict(self):
        for age,remaining in ((0,120000000),(119999999,1),(120000000,0),(600000000,0)):
            row=self.record(); row['points']['fixture_failure']=dict(age_us=age,remaining_us=remaining)
            self.assertEqual(self.valid(row),row)
        for point in (dict(age_us=600000001,remaining_us=0),dict(age_us=1,remaining_us=120000000),
                      dict(age_us=True,remaining_us=119999999),dict(age_us=120000000,remaining_us=1)):
            row=self.record(); row['points']['fixture_failure']=point
            with self.assertRaises(ValueError): self.valid(row)
        for cost in (dict(calls=0,total_us=1,max_us=1),dict(calls=1,total_us=10,max_us=11),
                     dict(calls=1,total_us=11,max_us=10),dict(calls=1000001,total_us=0,max_us=0),
                     dict(calls=1,total_us=600000001,max_us=600000000)):
            row=self.record(); row['pending_wait']['liveness']=cost
            with self.assertRaises(ValueError): self.valid(row)
        for entry,returned,valid in ((None,None,True),(0,None,True),(0,0,True),(2,1,False),(None,0,False),(600000001,None,False)):
            row=self.record(); row.update(worker_started_to_client_entry_us=entry,worker_started_to_client_return_us=returned)
            if valid: self.assertEqual(self.valid(row),row)
            else:
                with self.assertRaises(ValueError): self.valid(row)
        for purpose in (None,'Import','Sign','ResultService','private'):
            row=self.record(); row['worker_purpose']=purpose
            with self.assertRaises(ValueError): self.valid(row)
        for key,value in (('operation','Unknown'),('owner_budget_us',120000001),('version',True),('fixture_result','ReturnedOk')):
            row=self.record(); row[key]=value
            with self.assertRaises(ValueError): self.valid(row)

        expected={
            'WriterReconcile': {'AcquirePrepare','Acquire','ActivationPrepare','Activate','ReconcilePrepare','Reconcile'},
            'FinancialImport': {'Import'}, 'InitialSign': {'WalletReview','Sign'},
            'RetainedRetry': set(), 'ResultService': {'ResultService'},
        }
        self.assertEqual(set(expected),output.FLOW_OPERATION)
        self.assertEqual(len(output.LIFECYCLE_POINT_FIELDS),20)
        for operation,allowed in expected.items():
            for purpose in (None,*output.FLOW_JOB_PURPOSE):
                row=self.record(); row.update(operation=operation,worker_purpose=purpose,
                    worker_started_to_client_entry_us=None,worker_started_to_client_return_us=None)
                row['points']['after_drain']=None
                if purpose is None or purpose in allowed: self.assertEqual(self.valid(row),row)
                else:
                    with self.assertRaises(ValueError): self.valid(row)

    def test_split_oversize_duplicate_and_optional_failure_handling(self):
        raw=self.line().encode(); row=self.record()
        self.assertEqual(output.public_line(raw,'fixed'),('durable_lifecycle',row))
        self.assertEqual(output.public_line(b'test fixed ... '+raw,'fixed'),('durable_lifecycle',row))
        self.assertIsNone(output.public_line(b'private '+raw,'fixed'))
        self.assertIsNone(output.public_line((output.LIFECYCLE_PRIVATE_PREFIX+self.maximal+']').encode(),'fixed'))
        flow=output.DurableFlowDiagnostics(); flow.record('durable_flow',PublicDurableFlowTests().record())
        for first in (('durable_lifecycle',row),('durable_lifecycle_invalid',None)):
            capture=output.DurableLifecycleDiagnostics(); capture.record(*first); capture.record('durable_lifecycle',row)
            saved=io.StringIO()
            with contextlib.redirect_stdout(saved): capture.emit(flow)
            self.assertEqual(saved.getvalue(),output.LIFECYCLE_INVALID+'\n')
        for candidate in (raw+b' private',output.LIFECYCLE_PREFIX.encode()+b'\xff',b'CI_SYNTHETIC_DURABLE_LIFECYCLE{}'):
            self.assertEqual(output.public_line(candidate,'fixed'),('durable_lifecycle_invalid',None))
        for prefix in (b'',b'test fixed ... '):
            oversized=prefix+output.LIFECYCLE_PREFIX.encode()+b'x'*9000
            self.assertEqual(output.public_line(oversized,'fixed'),('durable_lifecycle_invalid',None))
            framing=output.BoundedLines('fixed'); lines=[]
            for at in range(0,len(oversized),111): lines.extend(framing.feed(oversized[at:at+111]))
            lines.extend(framing.feed(b'\n'))
            self.assertEqual(lines,[output.LIFECYCLE_INVALID.encode()]); self.assertLessEqual(len(framing.pending),8192)
        framing=output.BoundedLines('fixed'); cut=len(raw)//2
        self.assertEqual(framing.feed(raw[:cut]),[]); self.assertEqual(framing.feed(raw[cut:]+b'\n'),[raw])
        capture=output.DurableLifecycleDiagnostics(); capture.record('durable_lifecycle',row)
        with mock.patch('builtins.print',side_effect=OSError('private')): capture.emit(flow)
        with mock.patch.object(output.json,'dumps',side_effect=ValueError('private')): capture.emit(flow)

    def test_lifecycle_uses_existing_cleanup_phase_and_aggregate_gates(self):
        fake=PublicTimingTests().run_fake
        lines=[PublicDurableFlowTests().line(),self.line()]
        result=fake(lines,phase='durable-fixed-signing')
        self.assertIn(output.LIFECYCLE_PREFIX,result)
        self.assertLess(result.index('[JOINED_CLEANUP '),result.index(output.LIFECYCLE_PREFIX))
        for kwargs in (dict(verified=False),dict(cleanup_present=False)):
            self.assertNotIn(output.LIFECYCLE_PREFIX,fake(lines,phase='durable-fixed-signing',**kwargs))
        for phase in ('initial','full','durable-owner-reopen'):
            self.assertNotIn(output.LIFECYCLE_PREFIX,fake(lines,phase=phase,status=0))
        rolling=(self.base/'rolling_transcript_v1.rs').read_text()
        self.assertIn('pub(super) const MAX_BYTES: usize = 262_144;',rolling)
        self.assertEqual(rolling.split('pub(super) fn tail(',1)[0].count('self.durable_lifecycle.discard_for_budget();'),3)
        source=(ROOT/'scripts/ci-synthetic-output.py').read_text()
        gate=source.split('if phase in DURABLE_DIAGNOSTIC_PHASES and cleanup_observed:',1)[1].split("if phase=='full'",1)[0]
        self.assertIn('durable_lifecycle.emit(durable_flow)',gate)
        self.assertIn('if total > 16*1024*1024:',source)


class DurableAcquireReplyLossGateTests(unittest.TestCase):
    phase='durable-acquire-reply-loss'

    def diagnostic_lines(self):
        # Parser models only. They are never native-session or journal evidence.
        history=PublicHistoryMeasurementTests()
        admission=PublicAdmissionDiagnosticTests()
        flow=PublicDurableFlowTests().record()
        error=dict(stage='AcquireCall',domain='Signer',code='Uncertain',nested_code=None)
        flow.update(first_error=error.copy(),terminal_error=error.copy())
        flow['completion']=dict(purpose='Acquire',result='ReturnedErr',receive='Received',presentation='Suppressed')
        flow['call_outcomes']={key:'NotObserved' for key in output.FLOW_CALL_FIELDS}
        flow['call_outcomes']['writer_acquire']='ReturnedErr'
        lower=flow['lower_call_measurement']
        lower.update(purpose='Acquire',stage='ResponseRead',authority_code='Uncertain',io_kind='Closed',callback_stage=None)
        lower['measurement']['phase']='Acquire'
        flow['after_drain'].update(drain_result='ReturnedOk',drain_error=None,worker_purpose='Acquire',
                                   worker_result='ReturnedErr',worker_error=error.copy(),
                                   call_outcomes=flow['call_outcomes'].copy())
        lifecycle=PublicDurableLifecycleTests().record()
        lifecycle['worker_purpose']='Acquire'
        lifecycle['points']={key:None for key in output.LIFECYCLE_POINT_FIELDS}
        lifecycle['points']['fixture_failure']=dict(age_us=100000000,remaining_us=20000000)
        lifecycle['points']['after_drain']=dict(age_us=100000000,remaining_us=20000000)
        return ([history.line(history.record())]
                +[history.line(history.server_record(point),True) for point in output.HISTORY_SERVER_POINTS]
                +[admission.line(slot,row) for slot,row in enumerate(admission.records())]
                +[PublicDurableFlowTests().line(flow),PublicDurableLifecycleTests().line(lifecycle)])

    def test_acquire_diagnostics_use_existing_closed_schemas_only_after_verified_cleanup(self):
        lines=self.diagnostic_lines()
        prefixes=(output.HISTORY_MEASUREMENT_PREFIX,output.HISTORY_SERVER_MEASUREMENT_PREFIX,
                  *output.ADMISSION_PREFIXES,output.FLOW_PREFIX,output.LIFECYCLE_PREFIX)
        fake=PublicTimingTests().run_fake
        failed=fake(lines,phase=self.phase)
        self.assertNotIn('passed=true',failed)
        for prefix in prefixes:
            self.assertIn(prefix,failed)
            self.assertLess(failed.index('[JOINED_CLEANUP '),failed.index(prefix))
        for kwargs in (dict(verified=False),dict(cleanup_present=False),
                       dict(status=0,verified=False),dict(status=0,cleanup_present=False)):
            unverified=fake(lines,phase=self.phase,**kwargs)
            self.assertNotIn('passed=true',unverified)
            for prefix in prefixes: self.assertNotIn(prefix,unverified)
        for phase in ('initial','full','durable-owner-reopen'):
            unrelated=fake(lines,status=0,phase=phase)
            for prefix in prefixes: self.assertNotIn(prefix,unrelated)

    def test_acquire_success_has_no_terminal_loss_or_payment_claim_and_failure_stays_failure(self):
        fake=PublicTimingTests().run_fake
        result=fake([],status=0,phase=self.phase)
        self.assertIn('CI_SYNTHETIC_RESULT phase='+self.phase+' passed=true cleanup_verified=true',result)
        for forbidden in ('[JOINED_FAILURE ',output.FLOW_PREFIX,output.MARKER,
                          'WriterReconcileComplete','writer_reconcile_complete','signing_verified=true'):
            self.assertNotIn(forbidden,result)
        self.assertNotIn('passed=true',fake([],phase=self.phase))
        # An ordinary terminal failure is never special-cased into expected loss.
        with self.assertRaises(RuntimeError):
            fake([PublicOutputTests().failure()],status=0,phase=self.phase)
        # A payment DTO cannot be reinterpreted as an Acquire qualification.
        with self.assertRaises(ValueError):
            fake([output.MARKER+json.dumps(PublicOutputTests().record())],status=0,phase=self.phase)

    def test_acquire_unknown_private_truncated_and_stronger_diagnostics_are_withheld(self):
        fake=PublicTimingTests().run_fake
        name=output.TESTS[self.phase][0]
        private='private-session-receipt-or-key'
        raw=['CI_SYNTHETIC_ACQUIRE_RECEIPT '+private,'[DURABLE_FLOW_V1 '+private+']',
             'test another_selector ... '+output.FLOW_PREFIX+'{"private":"'+private+'"}',
             'WriterReconcileComplete '+private]
        for line in raw: self.assertIsNone(output.public_line(line.encode(),name))
        result=fake(raw,status=0,phase=self.phase)
        self.assertNotIn(private,result)
        self.assertNotIn('WriterReconcileComplete',result)
        row=PublicDurableFlowTests().record()
        for field,value in (('operation','AcquireReplyLoss'),('fixture_result','ReturnedOk')):
            changed=dict(row,**{field:value})
            with self.assertRaises(ValueError): output.public_durable_flow(json.dumps(changed))
        malformed=[output.FLOW_PREFIX+'{"private":"'+private+'"}',
                   self.diagnostic_lines()[-2][:-1],
                   output.LIFECYCLE_PREFIX+'{"private":"'+private+'"}']
        for line in malformed:
            projected=output.public_line(line.encode(),name)
            self.assertIn(projected[0],('durable_flow_invalid','durable_lifecycle_invalid'))
            result=fake([line],status=0,phase=self.phase)
            self.assertNotIn(private,result)
            self.assertIn('invalid=true details_withheld=true',result)
        # Optional malformed diagnostics cannot substitute for a failed scenario.
        self.assertNotIn('passed=true',fake(malformed,phase=self.phase))


class PrivateWorkspaceOutputTests(unittest.TestCase):
    def record(self):
        row={key:True for key in output.PRIVATE_WORKSPACE_BOOL_FIELDS}
        row.update({key:False for key in output.PRIVATE_WORKSPACE_FALSE_FIELDS})
        row.update(schema=1,phase='fixed_reopen',result='passed',first_failure=None,
                   producer_exit='sigkill',reader_exit='success',root_cleanup='closed_absent')
        return row

    def line(self,row=None):
        return output.PRIVATE_WORKSPACE_PREFIX+json.dumps(self.record() if row is None else row,separators=(',',':'))

    def test_private_workspace_exact_phase_and_unexpanded_clock_bounds(self):
        name=output.PREFIX+'durable_proposal_v1::private_fixed_v2::private_workspace_actual_process_death_reopens_same_fixed_proof'
        self.assertEqual(output.phase_selection('durable-private-reopen'),(name,1080,['--exact',name,'--test-threads=1','--ignored']))
        self.assertNotIn('durable-private-reopen',output.DURABLE_DIAGNOSTIC_PHASES)
        for phase in ('durable-private-queued','durable-private-reopen-v1','durable-private-reopen ','private-workspace-read-fixed-v1','durable-private-reopen*'):
            with self.assertRaises(KeyError): output.phase_selection(phase)
        shell=(ROOT/'scripts/ci-durable-native-linux.sh').read_text()
        call='TMPDIR="$runtime_root" python3 -B scripts/ci-synthetic-output.py "$executable" durable-private-reopen'
        self.assertEqual(shell.count(call),1)
        self.assertLess(shell.index('"$executable" storage-bootstrap'),shell.index(call))
        self.assertLess(shell.index(call),shell.index('"$executable" durable-owner-reopen'))
        self.assertIn('timeout-minutes: 150',(ROOT/'.github/workflows/durable-native-linux.yml').read_text())

    def test_private_workspace_closed_fields_and_22_diagnostic_boundaries(self):
        self.assertEqual(len(output.PRIVATE_WORKSPACE_BOUNDARIES),22)
        self.assertEqual(len(output.PRIVATE_WORKSPACE_FIELDS),20)
        row=self.record()
        self.assertEqual(output.public_private_workspace(json.dumps(row)),row)
        self.assertLess(len(json.dumps(row,separators=(',',':')).encode()),2048)
        for label in output.PRIVATE_WORKSPACE_BOUNDARIES:
            self.assertTrue(output.safe_failure(PublicOutputTests().failure(label+':EngineInvalidTransition')))
            self.assertFalse(output.safe_failure(PublicOutputTests().failure(label+':private-secret')))
        for key in output.PRIVATE_WORKSPACE_FIELDS:
            removed=row.copy(); removed.pop(key)
            with self.assertRaises(ValueError): output.public_private_workspace(json.dumps(removed))
        for key in ('password','path','hash','candidate_id','job_id','timestamp','pid','errno','counts','extensions'):
            with self.assertRaises(ValueError): output.public_private_workspace(json.dumps(dict(row,**{key:'private-value'})))
        duplicate=json.dumps(row)[:-1]+',"schema":1}'
        with self.assertRaises(ValueError): output.public_private_workspace(duplicate)
        with self.assertRaises(ValueError): output.public_private_workspace(' '*2049+json.dumps(row))

    def test_private_workspace_rejects_type_confusion_and_stronger_claims(self):
        row=self.record()
        for key in output.PRIVATE_WORKSPACE_BOOL_FIELDS:
            for value in (1,0,'true',None,[],{}):
                with self.assertRaises(ValueError): output.public_private_workspace(json.dumps(dict(row,**{key:value})))
        for key in output.PRIVATE_WORKSPACE_FALSE_FIELDS:
            for value in (True,0,'false',None):
                with self.assertRaises(ValueError): output.public_private_workspace(json.dumps(dict(row,**{key:value})))
        for key,value in (('schema',True),('schema',1.0),('phase','queued'),('result','success'),('producer_exit','success'),('reader_exit','sigkill'),('root_cleanup','closed'),('first_failure','/private/path')):
            with self.assertRaises(ValueError): output.public_private_workspace(json.dumps(dict(row,**{key:value})))

    def test_private_workspace_every_missing_success_condition_fails(self):
        row=self.record()
        for key in output.PRIVATE_WORKSPACE_BOOL_FIELDS:
            with self.assertRaises(ValueError): output.public_private_workspace(json.dumps(dict(row,**{key:False})))
        for key,value in (('first_failure','PrivateWorkspaceProof'),('producer_exit','other'),('producer_exit','unverified'),('reader_exit','other'),('reader_exit','not_started'),('reader_exit','unverified'),('root_cleanup','retained'),('root_cleanup','unverified')):
            with self.assertRaises(ValueError): output.public_private_workspace(json.dumps(dict(row,**{key:value})))
        failed=dict(row,result='failed',first_failure='PrivateWorkspaceProof',reader_exit='not_started',reader_reaped=False,reader_group_absent=False)
        self.assertEqual(output.public_private_workspace(json.dumps(failed)),failed)
        with self.assertRaises(ValueError): output.public_private_workspace(json.dumps(dict(row,result='failed')))

    def test_private_workspace_fragmented_bounded_lines_never_forward_private_text(self):
        line=self.line().encode()
        for split in range(len(line)+1):
            parser=output.BoundedLines('exact')
            self.assertEqual(parser.feed(line[:split]),[])
            self.assertEqual(parser.feed(line[split:]+b'\n'),[line])
        self.assertEqual(output.public_line(b'test exact ... '+line,'exact'),('private_workspace',self.record()))
        self.assertIsNone(output.public_line(b'private text '+line,'exact'))
        self.assertIsNone(output.public_line(b'SYNTHETIC_PRIVATE_FIXED_DURABLE_V1=1','exact'))
        self.assertIsNone(output.public_line(b'{"private_control":"secret"}','exact'))
        for raw in (line[:-1],b'CI_SYNTHETIC_PRIVATE_WORKSPACE '+bytes([255]),b'CI_SYNTHETIC_PRIVATE_WORKSPACE_BAD '+line):
            with self.assertRaises(ValueError): output.public_line(raw,'exact')
        parser=output.BoundedLines('exact')
        framed=parser.feed(b'CI_SYNTHETIC_PRIVATE_WORKSPACE '+b'x'*9000+b'\n'+line+b'\n')
        self.assertEqual(framed[0],output.PRIVATE_WORKSPACE_INVALID.encode())
        with self.assertRaises(ValueError): output.public_line(framed[0],'exact')
        self.assertLessEqual(len(parser.pending),8192)

    def run_fake(self,rows,status=0,phase='durable-private-reopen'):
        name=output.TESTS[phase][0]
        core='[JOINED_CORE_POLICY inherited_limit=Zero collector=Pipe process_dumpability=Unchanged crash_copy_absence_verified=false]'
        payload=('\n'.join([core]+rows)+'\n').encode()
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
            output.run('/verified/host',phase)
        return captured.getvalue()

    def test_private_workspace_phase_requires_one_aggregate_and_libtest_success(self):
        text=self.run_fake([self.line()])
        self.assertIn('CI_SYNTHETIC_RESULT phase=durable-private-reopen passed=true',text)
        self.assertEqual(text.count(output.PRIVATE_WORKSPACE_PREFIX),1)
        with self.assertRaises(RuntimeError): self.run_fake([])
        with self.assertRaises(RuntimeError): self.run_fake([self.line()],status=101)
        with self.assertRaises(ValueError): self.run_fake([self.line(),self.line()])
        with self.assertRaises(ValueError): self.run_fake([self.line()],phase='durable-owner-reopen')
        cleanup='[JOINED_CLEANUP group_signal=AlreadyAbsentWhileLeaderOwned group_absence=OriginalGroupAbsentObserved direct_child=Reaped root_cleanup=ClosedAndAbsenceVerified exit=Some(0) signal=None core_dumped=false]'
        with self.assertRaises(ValueError): self.run_fake([cleanup,self.line()])
        with self.assertRaises(ValueError): self.run_fake([output.MARKER+json.dumps(PublicOutputTests().record()),self.line()])

    def test_private_workspace_pure_catalogue_matches_exact_source_tests(self):
        base=ROOT/'crates/wholepact-native-host/src/host/manual_enrollment/command/roster_publication_v2/sequential_construction_v3_qualification'
        source=(base/'durable_proposal_v1/private_fixed_v2.rs').read_text().split('mod pure_tests {',1)[1]
        names=re.findall(r'#\[test\]\s*fn ([a-z0-9_]+)\(',source)
        expected=tuple(output.PREFIX+'durable_proposal_v1::private_fixed_v2::pure_tests::'+name for name in names)
        self.assertEqual(expected,output.PRIVATE_WORKSPACE_PURE_TESTS)
        self.assertEqual(len(set(expected)),len(names))
        combined=(output.PURE_TESTS+output.PRIVATE_WORKSPACE_PURE_TESTS+output.PRIVATE_FIXED_PROJECTION_TESTS+output.PRIVATE_FIXED_TRANSCRIPT_TESTS+output.POLICY_ENVELOPE_TESTS+output.PROMPT_RENDERING_TESTS+output.LOWER_ERROR_TESTS+output.DENIAL_TESTS+output.ROLLING_TRANSCRIPT_TESTS+output.AUTHORITY_PROJECTION_TESTS+output.READ_WAVE_TESTS+output.HISTORY_MEASUREMENT_TESTS+output.HISTORY_TRANSCRIPT_TESTS+output.ADMISSION_PROJECTION_TESTS+output.ADMISSION_TRANSCRIPT_TESTS+output.ADMISSION_HOST_TESTS+output.FLOW_PROJECTION_TESTS+output.FLOW_TRANSCRIPT_TESTS+output.FLOW_HOST_TESTS+output.TIMING_HOST_TESTS+(output.DURABLE_PROVIDER_METADATA_TEST,))
        self.assertEqual(len(set(combined)),len(combined))



class PrivateFixedDiagnosticOutputTests(unittest.TestCase):
    FIXTURE = r'''{"evidence":{"attempt_consumed":true,"call_scope":"CurrentInvocation","calls":{"enqueue":"NotApplicable","freeze":"NotApplicable","link":"NotApplicable","outcome":"NotCalled","proof":"ReturnedErrUnknown","receipt":"NotApplicable"}},"primary":{"cause":"Authentication","engine_code":"NotApplicable","family":"Host","operation":"Proof","site":"HostProofForegroundMessage"},"schema":1,"stage":null,"worker":{"engine_failure":{"attempt_consumed":true,"call_scope":"CurrentInvocation","calls":{"enqueue":"NotApplicable","freeze":"NotApplicable","link":"NotApplicable","outcome":"NotCalled","proof":"ReturnedErrUnknown","receipt":"NotApplicable"},"cause":"NoCurrentObservation","engine_code":"DURABLE_CONSTRUCTION_UNAVAILABLE","family":"Sync","operation":"Proof","schema":1,"site":"ProofRun"},"join":"Joined","result":"ReceivedErr"}}'''
    MAXIMAL = r'''{"evidence":{"attempt_consumed":true,"call_scope":"CurrentInvocation","calls":{"enqueue":"NotApplicable","freeze":"NotApplicable","link":"NotApplicable","outcome":"ReturnedErrUnknown","proof":"ReturnedErrUnknown","receipt":"NotApplicable"}},"primary":{"cause":"RETAINED_INPUT_OBSERVATION_UNAVAILABLE","engine_code":"RETAINED_INPUT_OBSERVATION_UNAVAILABLE","family":"Engine","operation":"Proof","site":"ReaderOriginalFinancialProofSchema"},"schema":1,"stage":{"callback_count":1000000,"callback_max_us":1080000000,"callback_total_us":1080000000,"elapsed_ms":1080000,"kind":"ProveOriginal"},"worker":{"engine_failure":{"attempt_consumed":true,"call_scope":"CurrentInvocation","calls":{"enqueue":"NotApplicable","freeze":"NotApplicable","link":"NotApplicable","outcome":"ReturnedErrUnknown","proof":"ReturnedErrUnknown","receipt":"NotApplicable"},"cause":"RETAINED_INPUT_OBSERVATION_UNAVAILABLE","engine_code":"RETAINED_INPUT_OBSERVATION_UNAVAILABLE","family":"Engine","operation":"Proof","schema":1,"site":"SnapshotSourceUnchanged"},"join":"Panicked","result":"ReceivedErr"}}'''

    def record(self):
        return json.loads(self.FIXTURE)

    def line(self, row=None):
        return output.PRIVATE_FIXED_DIAGNOSTIC_PREFIX+json.dumps(self.record() if row is None else row,separators=(',',':'),sort_keys=True)

    def check(self, row):
        return output.public_private_fixed_diagnostic(json.dumps(row))

    def objects(self, row):
        return [row,row['primary'],row['evidence'],row['evidence']['calls'],row['worker'],row['worker']['engine_failure'],row['worker']['engine_failure']['calls']]

    def test_exact_schema_required_fields_types_enums_and_pairing(self):
        self.assertEqual(self.check(self.record()),self.record())
        for index, original in enumerate(self.objects(self.record())):
            for key in original:
                row=self.record(); del self.objects(row)[index][key]
                with self.assertRaises(ValueError): self.check(row)
                row=self.record(); self.objects(row)[index][key]=['PRIVATE_CANARY']
                with self.assertRaises(ValueError): self.check(row)
            row=self.record(); self.objects(row)[index]['private_unknown']='PRIVATE_CANARY'
            with self.assertRaises(ValueError): self.check(row)
        for family, causes in output.PRIVATE_FIXED_FAMILIES.items():
            for cause in set().union(*output.PRIVATE_FIXED_FAMILIES.values()):
                row=self.record(); row['primary'].update(family=family,cause=cause,engine_code='Unclassified' if family=='Engine' else 'NotApplicable')
                if cause in causes: self.assertEqual(self.check(row),row)
                else:
                    with self.assertRaises(ValueError): self.check(row)
        for operation in output.PRIVATE_FIXED_OPERATIONS:
            row=self.record(); row['worker']=None; row['primary']['operation']=operation
            row['evidence']['attempt_consumed']=operation=='Proof'
            row['evidence']['calls']={slot:'NotCalled' if slot in output.PRIVATE_FIXED_RELEVANCE[operation] else 'NotApplicable' for slot in output.PRIVATE_FIXED_CALL_FIELDS}
            self.assertEqual(self.check(row),row)
            for slot in output.PRIVATE_FIXED_CALL_FIELDS:
                for state in output.PRIVATE_FIXED_CALL_STATES:
                    changed=json.loads(json.dumps(row)); changed['evidence']['calls'][slot]=state
                    allowed=output.PRIVATE_FIXED_SLOT_STATES[slot] if slot in output.PRIVATE_FIXED_RELEVANCE[operation] else {'NotApplicable'}
                    if state in allowed: self.assertEqual(self.check(changed),changed)
                    else:
                        with self.assertRaises(ValueError): self.check(changed)
        row=self.record(); row['primary'].update(family='Engine',cause='Unclassified')
        with self.assertRaises(ValueError): self.check(row)
        for schema in (True,False,0,2,1.0,'1',None):
            row=self.record(); row['schema']=schema
            with self.assertRaises(ValueError): self.check(row)

    def test_worker_null_receive_join_and_nullable_call_evidence(self):
        for operation in output.PRIVATE_FIXED_OPERATIONS:
            row=self.record(); row['primary']['operation']=operation; row['worker']=None; row['evidence']=None
            self.assertEqual(self.check(row),row)
        for result in output.PRIVATE_FIXED_WORKER_RESULTS:
            for join in output.PRIVATE_FIXED_WORKER_JOINS:
                row=self.record(); row['evidence']=None
                row['worker']={'result':result,'join':join,'engine_failure':None}
                if (result=='NotStarted')==(join=='NotStarted'): self.assertEqual(self.check(row),row)
                else:
                    with self.assertRaises(ValueError): self.check(row)
                row['evidence']=self.record()['evidence']; row['worker']['engine_failure']=self.record()['worker']['engine_failure']
                if result=='ReceivedErr' and join!='NotStarted': self.assertEqual(self.check(row),row)
                else:
                    with self.assertRaises(ValueError): self.check(row)
        for section,key,value in [('primary','operation','Checkpoint'),('evidence','attempt_consumed',False),('evidence','attempt_consumed',1),('worker','engine_failure',None)]:
            row=self.record(); row[section][key]=value
            with self.assertRaises(ValueError): self.check(row)
        for key,value in [('operation','Checkpoint'),('site','HostProofJoin'),('engine_code','NotApplicable'),('attempt_consumed',False),('schema',True),('call_scope','EarlierInvocation')]:
            row=self.record(); row['worker']['engine_failure'][key]=value
            with self.assertRaises(ValueError): self.check(row)
        row=self.record(); row['worker']['engine_failure']['calls']['proof']='ReturnedOk'
        with self.assertRaises(ValueError): self.check(row)

    def test_stage_cost_exact_pairing_bounds_and_required_null(self):
        for kind,operation in output.PRIVATE_FIXED_STAGE_OPERATIONS.items():
            row=self.record(); row['primary']['operation']=operation; row['worker']=None; row['evidence']=None
            row['stage']={'kind':kind,'elapsed_ms':120001,'callback_count':1,'callback_total_us':7,'callback_max_us':7}
            self.assertEqual(self.check(row),row)
            row['primary']['operation']='OpenOriginal'
            with self.assertRaises(ValueError): self.check(row)
        row=json.loads(self.MAXIMAL)
        for key,bad in [('elapsed_ms',1080001),('callback_count',1000001),('callback_total_us',1080000001),('callback_max_us',1080000001),('kind','private-canary')]:
            changed=json.loads(self.MAXIMAL);changed['stage'][key]=bad
            with self.assertRaises(ValueError): self.check(changed)
        for key in output.PRIVATE_FIXED_STAGE_FIELDS:
            changed=json.loads(self.MAXIMAL);del changed['stage'][key]
            with self.assertRaises(ValueError): self.check(changed)
            changed=json.loads(self.MAXIMAL);changed['stage'][key]=True
            with self.assertRaises(ValueError): self.check(changed)
        changed=self.record();del changed['stage']
        with self.assertRaises(ValueError): self.check(changed)
        for stage in [{'kind':'ProveOriginal','elapsed_ms':0,'callback_count':1,'callback_total_us':2,'callback_max_us':1}, {'kind':'ProveOriginal','elapsed_ms':0,'callback_count':0,'callback_total_us':1,'callback_max_us':1}, {'kind':'ProveOriginal','elapsed_ms':0,'callback_count':1,'callback_total_us':1,'callback_max_us':2}]:
            changed=self.record();changed['stage']=stage
            with self.assertRaises(ValueError): self.check(changed)
        raw=self.MAXIMAL.replace('"elapsed_ms":1080000','"elapsed_ms":1080000,"elapsed_ms":1')
        with self.assertRaises(ValueError): output.public_private_fixed_diagnostic(raw)
        raw=self.MAXIMAL.replace('"kind":"ProveOriginal"','"kind":"ProveOriginal","private":"canary"')
        with self.assertRaises(ValueError): output.public_private_fixed_diagnostic(raw)

    def test_maximal_canonical_record_is_bounded(self):
        row=output.public_private_fixed_diagnostic(self.MAXIMAL)
        canonical=json.dumps(row,separators=(',',':'),sort_keys=True)
        self.assertLessEqual(len(canonical.encode()),4096)
        exact=' '*(4096-len(canonical.encode()))+canonical
        self.assertEqual(len(exact.encode()),4096)
        self.assertEqual(output.public_private_fixed_diagnostic(exact),row)
        with self.assertRaises(ValueError): output.public_private_fixed_diagnostic(exact+' ')
        raw=(output.PRIVATE_FIXED_DIAGNOSTIC_PREFIX+canonical+'\r'*4097).encode()
        self.assertEqual(output.public_line(raw,'exact'),('private_fixed_diagnostic_invalid',None))

    def test_unknown_private_duplicate_and_oversized_records_withheld(self):
        for index, original in enumerate(self.objects(self.record())):
            for key in original:
                obj=json.dumps(original,separators=(',',':'),sort_keys=True)
                duplicate='{'+json.dumps(key)+':'+json.dumps(original[key])+','+obj[1:]
                row=self.record(); target=self.objects(row)[index]
                def encode(value):
                    if value is target: return duplicate
                    if type(value) is dict: return '{'+','.join(json.dumps(k)+':'+encode(v) for k,v in sorted(value.items()))+'}'
                    return json.dumps(value,separators=(',',':'))
                raw=encode(row)
                with self.assertRaises(ValueError): output.public_private_fixed_diagnostic(raw)
        for key in output.PRIVATE_FIXED_PRIMARY_FIELDS:
            row=self.record(); row['primary'][key]='/private/PCZT-FVK-CANARY'
            self.assertEqual(output.public_line(self.line(row).encode(),'exact'),('private_fixed_diagnostic_invalid',None))
        row=self.record(); row['primary'].update(family='Sync',cause='Authentication')
        with self.assertRaises(ValueError): self.check(row)
        capture=output.PrivateFixedDiagnostics()
        capture.record('private_fixed_diagnostic',self.record())
        capture.record('private_fixed_diagnostic_invalid',None)
        self.assertTrue(capture.invalid)
        self.assertEqual(capture.value,self.record())
        for raw in ((output.PRIVATE_FIXED_DIAGNOSTIC_PREFIX+' '*4097+'{}').encode(),output.PRIVATE_FIXED_DIAGNOSTIC_PREFIX.encode()+bytes([255]),output.PRIVATE_FIXED_DIAGNOSTIC_UNAVAILABLE.encode()):
            self.assertEqual(output.public_line(raw,'exact'),('private_fixed_diagnostic_invalid',None))

    def test_fragmented_crlf_utf8_and_near_prefix_do_not_leak(self):
        line=self.line().encode()
        for split in range(len(line)+1):
            parser=output.BoundedLines('exact')
            self.assertEqual(parser.feed(line[:split]),[])
            rows=parser.feed(line[split:]+b'\r\n')
            self.assertEqual([output.public_line(row,'exact') for row in rows],[('private_fixed_diagnostic',self.record())])
        for raw in (b'private '+line,b'[ '+line+b' ]',b'CI_SYNTHETIC_PRIVATE_FIXED_DIAGNOSTI '+line):
            self.assertIsNone(output.public_line(raw,'exact'))
        self.assertEqual(output.public_line(b'test exact ... '+line,'exact'),('private_fixed_diagnostic',self.record()))
        self.assertEqual(output.public_line(b'CI_SYNTHETIC_PRIVATE_FIXED_DIAGNOSTIC_BAD '+line,'exact'),('private_fixed_diagnostic_invalid',None))
        parser=output.BoundedLines('exact')
        framed=parser.feed(output.PRIVATE_FIXED_DIAGNOSTIC_PREFIX.encode()+b'x'*9000+b'\n'+line+b'\n')
        self.assertEqual(framed[0],output.PRIVATE_FIXED_DIAGNOSTIC_UNAVAILABLE.encode())
        self.assertEqual(output.public_line(framed[1],'exact'),('private_fixed_diagnostic',self.record()))
        self.assertLessEqual(len(parser.pending),8192)
        parser=output.BoundedLines('exact')
        self.assertEqual(parser.feed('private é'.encode()[:-1]),[])
        self.assertIsNone(output.public_line(parser.feed(bytes([0xa9])+b'\n')[0],'exact'))

    def failed_outcome(self):
        row=PrivateWorkspaceOutputTests().record()
        row.update(result='failed',first_failure='PrivateWorkspaceProof',producer_exit='other',reader_exit='not_started',reader_reaped=False,reader_group_absent=False)
        return row

    def run_fake(self, rows, status=101, phase='durable-private-reopen', tail=b''):
        name=output.TESTS[phase][0]
        core='[JOINED_CORE_POLICY inherited_limit=Zero collector=Pipe process_dumpability=Unchanged crash_copy_absence_verified=false]'
        payload=('\n'.join([core]+rows)+'\n').encode()+tail
        stream=mock.Mock(); stream.fileno.return_value=7
        process=mock.Mock(stdout=stream); process.wait.return_value=status
        listed=output.subprocess.CompletedProcess([],0,(name+': test\n\n1 test, 0 benchmarks\n').encode(),b'')
        captured=io.StringIO(); failed=False
        with mock.patch.object(output.resource,'getrlimit',return_value=(0,0)), \
             mock.patch.object(output.subprocess,'run',return_value=listed), \
             mock.patch.object(output.subprocess,'Popen',return_value=process), \
             mock.patch.object(output.select,'select',return_value=([stream],[],[])), \
             mock.patch.object(output.os,'read',side_effect=[payload,b'']), \
             mock.patch.dict(output.os.environ,{},clear=True), contextlib.redirect_stdout(captured):
            try: output.run('/verified/host',phase)
            except RuntimeError: failed=True
        return failed,captured.getvalue()

    def test_record_does_not_change_phase_success_or_first_failure(self):
        aggregate=output.PRIVATE_WORKSPACE_PREFIX+json.dumps(self.failed_outcome())
        for records in ([],[self.line()],[self.line(),self.line()],[output.PRIVATE_FIXED_DIAGNOSTIC_UNAVAILABLE]):
            failed,text=self.run_fake(records+[aggregate])
            self.assertTrue(failed)
            projected=[line for line in text.splitlines() if line.startswith(output.PRIVATE_WORKSPACE_PREFIX)]
            self.assertEqual(len(projected),1)
            self.assertEqual(json.loads(projected[0][len(output.PRIVATE_WORKSPACE_PREFIX):]),self.failed_outcome())
        failed,text=self.run_fake([self.line()])
        self.assertTrue(failed); self.assertNotIn(output.PRIVATE_FIXED_DIAGNOSTIC_PREFIX,text)
        for records in ([self.line()],[self.line(),self.line()],[output.PRIVATE_FIXED_DIAGNOSTIC_UNAVAILABLE]):
            aggregate=PrivateWorkspaceOutputTests().line()
            failed,text=self.run_fake(records+[aggregate],status=0)
            self.assertFalse(failed); self.assertNotIn('CI_SYNTHETIC_PRIVATE_FIXED_DIAGNOSTIC',text)
        failed,text=self.run_fake([aggregate],tail=self.line().encode())
        self.assertTrue(failed); self.assertNotIn('CI_SYNTHETIC_PRIVATE_FIXED_DIAGNOSTIC',text)

    def test_record_forwarded_only_after_existing_cleanup_outcome(self):
        row=self.failed_outcome()
        aggregate=lambda value:output.PRIVATE_WORKSPACE_PREFIX+json.dumps(value)
        failed,text=self.run_fake([self.line(),aggregate(row)])
        self.assertTrue(failed)
        self.assertIn(self.line(),text)
        for key,value in [('root_cleanup','retained'),('root_cleanup','unverified'),('producer_reaped',False),('producer_group_absent',False),('producer_exit','unverified'),('reader_exit','unverified'),('reader_exit','other')]:
            changed=dict(row,**{key:value})
            failed,text=self.run_fake([self.line(),aggregate(changed)])
            self.assertTrue(failed); self.assertNotIn('CI_SYNTHETIC_PRIVATE_FIXED_DIAGNOSTIC',text)
        reader=dict(row,reader_exit='other',reader_reaped=True,reader_group_absent=True)
        failed,text=self.run_fake([self.line(),aggregate(reader)])
        self.assertTrue(failed); self.assertIn(self.line(),text)
        failed,text=self.run_fake([self.line(),self.line(),aggregate(row)])
        self.assertEqual(text.count(output.PRIVATE_FIXED_DIAGNOSTIC_UNAVAILABLE),1)
        self.assertNotIn(self.line(),text)
        failed,text=self.run_fake([aggregate(row)],tail=self.line().encode())
        self.assertIn(output.PRIVATE_FIXED_DIAGNOSTIC_UNAVAILABLE,text)
        failed,text=self.run_fake([self.line()],phase='durable-owner-reopen')
        self.assertTrue(failed); self.assertNotIn('CI_SYNTHETIC_PRIVATE_FIXED_DIAGNOSTIC',text)

    def test_rust_python_closed_inventory_and_selector_parity(self):
        leaf=(ROOT/'crates/wholepact-native-host/src/host/financial/private_durable_fixed_v2.rs').read_text()
        def variants(name):
            body=re.search(r'enum '+name+r'\s*\{(.*?)\}',leaf,re.S).group(1)
            return frozenset(re.findall(r'\b([A-Za-z][A-Za-z0-9_]*)\s*(?:,|$)',body))
        for name, expected in [('Operation',output.PRIVATE_FIXED_OPERATIONS),('Site',output.PRIVATE_FIXED_SITES),('Family',set(output.PRIVATE_FIXED_FAMILIES)),('Cause',set().union(*output.PRIVATE_FIXED_FAMILIES.values())),('EngineCode',output.PRIVATE_FIXED_ENGINE_CODES),('CallState',output.PRIVATE_FIXED_CALL_STATES),('CallScope',{'CurrentInvocation'}),('WorkerResult',output.PRIVATE_FIXED_WORKER_RESULTS),('WorkerJoin',output.PRIVATE_FIXED_WORKER_JOINS)]:
            self.assertEqual(variants('PrivateDiagnostic'+name+'V1'),expected)
        self.assertEqual(variants('PrivateStageKindV1'),set(output.PRIVATE_FIXED_STAGE_OPERATIONS))
        for name, expected in [('PrivateFixedDiagnosticV1',output.PRIVATE_FIXED_FIELDS),('PrivateDiagnosticPrimaryV1',output.PRIVATE_FIXED_PRIMARY_FIELDS),('PrivateDiagnosticEvidenceV1',output.PRIVATE_FIXED_EVIDENCE_FIELDS),('PrivateDiagnosticCallsV1',output.PRIVATE_FIXED_CALL_FIELDS),('PrivateDiagnosticEngineCoreV1',output.PRIVATE_FIXED_ENGINE_FIELDS),('PrivateDiagnosticWorkerV1',output.PRIVATE_FIXED_WORKER_FIELDS),('PrivateStageCostV1',output.PRIVATE_FIXED_STAGE_FIELDS)]:
            body=re.search(r'struct '+name+r'\s*\{(.*?)\n\}',leaf,re.S).group(1)
            self.assertEqual(set(re.findall(r'pub\(crate\)\s+(\w+)\s*:',body)),expected)
        families={family:frozenset(re.findall(r'C::(\w+)',causes)) for family,causes in re.findall(r'F::(\w+)\s*=>\s*matches!\(\s*self.cause,\s*(.*?)\)',leaf,re.S)}
        self.assertEqual(families,output.PRIVATE_FIXED_FAMILIES)
        engine=leaf.split('impl PrivateDiagnosticEngineCoreV1 {',1)[1].split('fn from_error',1)[0]
        self.assertEqual(set(re.findall(r'PrivateDiagnosticSiteV1::(\w+)',engine)),output.PRIVATE_FIXED_ENGINE_SITES)
        base=ROOT/'crates/wholepact-native-host/src/host/manual_enrollment/command/roster_publication_v2/sequential_construction_v3_qualification'
        safe=(base/'safe_diagnostics_v1.rs').read_text(); rolling=(base/'rolling_transcript_v1.rs').read_text()
        for source, module, selected in [(safe,'safe_diagnostics_v1::',output.PRIVATE_FIXED_PROJECTION_TESTS),(rolling,'rolling_transcript_v1::tests::',output.PRIVATE_FIXED_TRANSCRIPT_TESTS)]:
            actual=re.findall(r'#\[test\]\s*(?:#\[[^\]]*\]\s*)*fn (private_fixed_diagnostic_\w+)\(',source)
            self.assertEqual(tuple(output.PREFIX+module+name for name in actual),selected)
            self.assertEqual(len(actual),len(set(actual)))
        fixture=re.search(r'PRIVATE_FIXED_DIAGNOSTIC_TEST_JSON: &str = r#"(.*?)"#;',safe,re.S).group(1)
        maximal=re.search(r'PRIVATE_FIXED_DIAGNOSTIC_MAXIMAL_TEST_JSON: &str = r#"(.*?)"#;',safe,re.S).group(1)
        self.assertEqual(json.loads(fixture),self.record())
        self.assertEqual(json.loads(maximal),json.loads(self.MAXIMAL))
        # Existing budget, outcome and deadline code remains authoritative.
        self.assertIn('MAX_BYTES: usize = 262_144',rolling)
        self.assertEqual(len(output.PRIVATE_WORKSPACE_FIELDS),20)
        self.assertEqual(output.TESTS['durable-private-reopen'][1],1080)


class DurableDeliveryOutputTests(unittest.TestCase):
    def record(self):
        row={key:True for key in output.DURABLE_DELIVERY_BOOL_FIELDS}
        row.update({key:False for key in output.DURABLE_DELIVERY_FALSE_FIELDS})
        row.update(schema=4,phase='durable_delivery_admission',result='passed',first_failure=None,
                   first_outcome=None,failed_child_inputs_completed=None,failed_child_inputs_expected=None,
                   retained_exporter_failure=None,retained_exporter_outcome=None,
                   producer_exit='sigkill',reader_exit='success',root_cleanup='closed_absent',admission_count='2_of_2')
        return row
    def line(self,row=None):
        return output.DURABLE_DELIVERY_PREFIX+json.dumps(self.record() if row is None else row,separators=(',',':'))
    def test_exact_new_phase_preserves_original_gates_and_bounds(self):
        name=output.PREFIX+'durable_proposal_v1::delivery_admission_v2::durable_delivery_native_v3_admission_reopens_original_after_process_death'
        self.assertEqual(output.phase_selection('durable-delivery-admission'),(name,1080,['--exact',name,'--test-threads=1','--ignored']))
        shell=(ROOT/'scripts/ci-durable-native-linux.sh').read_text()
        call='TMPDIR="$runtime_root" python3 -B scripts/ci-synthetic-output.py "$executable" durable-delivery-admission'
        self.assertEqual(shell.count(call),1)
        self.assertLess(shell.index('"$executable" storage-bootstrap'),shell.index(call))
        self.assertNotIn('"$executable" durable-private-reopen',shell)
        self.assertNotIn('"$executable" durable-fixed-signing',shell)
        self.assertIn('B1',shell)
        self.assertEqual(output.TESTS['durable-private-reopen'][1],1080)
        self.assertNotIn('durable-delivery-admission',output.DURABLE_DIAGNOSTIC_PHASES)
    def test_rust_python_result_inventory_and_selector_are_exact(self):
        base=ROOT/'crates/wholepact-native-host/src/host/manual_enrollment/command/roster_publication_v2/sequential_construction_v3_qualification'
        source=(base/'durable_proposal_v1/delivery_admission_v2.rs').read_text()
        fields=re.search(r'struct PublicOutcomeV4\s*\{(.*?)\n\}',source,re.S).group(1)
        skipped=re.findall(r'#\[serde\(skip\)\]\s*(\w+): ([^,]+),',fields)
        self.assertEqual(skipped,[('pending_child_observation','Option<FailedChildObservation>')])
        fields=re.sub(r'#\[serde\(skip\)\]\s*\w+: [^,]+,','',fields)
        actual=dict(re.findall(r'^\s+(\w+): ([^,]+),$',fields,re.M))
        self.assertEqual(set(actual),output.DURABLE_DELIVERY_FIELDS)
        self.assertEqual({key for key,ty in actual.items() if ty=='bool'},output.DURABLE_DELIVERY_BOOL_FIELDS|output.DURABLE_DELIVERY_FALSE_FIELDS)
        self.assertIn('const BOUNDARIES: &[&str] = diagnostic::DELIVERY_BOUNDARIES;',source)
        safe=(base/'safe_diagnostics_v1.rs').read_text()
        boundaries=re.search(r'const DELIVERY_BOUNDARIES: &\[&str\] = &\[(.*?)\];',safe,re.S).group(1)
        self.assertEqual(set(re.findall(r'"(\w+)"',boundaries)),output.DURABLE_DELIVERY_BOUNDARIES)
        self.assertIn('const PUBLIC_PREFIX: &str = "'+output.DURABLE_DELIVERY_PREFIX+'";',source)
        selector=output.TESTS['durable-delivery-admission'][0].rsplit('::',1)[1]
        self.assertEqual(len(re.findall(r'#\[test\]\s*#\[ignore = "[^"\n]+"\]\s*fn '+selector+r'\(\)',source)),1)
        public=source.split('fn public_json(&self)',1)[1].split('pub(in crate::host',1)[0]
        self.assertRegex(public,r'serialize_delivery_with_exporter_priority\(\s*serde_json::to_value\(self\)\.map_err\(\|_\| invalid\(\)\)\?,\s*2048,\s*\)')
        serializer=source.split('fn serialize_delivery_with_exporter_priority(',1)[1].split('\n}\n',1)[0]
        self.assertEqual(serializer.count('if json.len() > maximum'),2)
        self.assertRegex(serializer,r'if json\.len\(\) > maximum\s*\{\s*return Err\(invalid\(\)\);\s*\}\s*Ok\(json\)')
        self.assertIn('Duration::from_secs(900)',source)
    def test_closed_fields_duplicate_types_and_claims_are_strict(self):
        row=self.record()
        self.assertEqual(output.public_durable_delivery(json.dumps(row)),row)
        self.assertLess(len(self.line().encode()),2048)
        for key in output.DURABLE_DELIVERY_FIELDS:
            missing=row.copy();missing.pop(key)
            with self.assertRaises(ValueError):output.public_durable_delivery(json.dumps(missing))
        for key in output.DURABLE_DELIVERY_BOOL_FIELDS:
            for value in (1,0,None,'true'):
                with self.assertRaises(ValueError):output.public_durable_delivery(json.dumps(dict(row,**{key:value})))
        for key in output.DURABLE_DELIVERY_FALSE_FIELDS:
            with self.assertRaises(ValueError):output.public_durable_delivery(json.dumps(dict(row,**{key:True})))
        for bad in (json.dumps(row)[:-1]+',"schema":2}',json.dumps(dict(row,private_key='secret')),' '*2049+json.dumps(row)):
            with self.assertRaises(ValueError):output.public_durable_delivery(bad)
    def test_first_observed_outcome_and_input_progress_are_closed_and_cleanup_gated(self):
        row=dict(self.record(),result='failed',first_failure='DeliveryRedisclosureServe',
                 first_outcome='BridgePermission',failed_child_inputs_completed=108,
                 failed_child_inputs_expected=117)
        self.assertEqual(output.public_durable_delivery(json.dumps(row)),row)
        for value in ('private secret','Begin','Complete','',1,{},['BridgePermission']):
            with self.assertRaises(ValueError):
                output.public_durable_delivery(json.dumps(dict(row,first_outcome=value)))
        for completed,expected in ((True,117),(1,False),(-1,117),(118,117),(1,513),(0,0),(None,117),(108,None),('108',117)):
            with self.assertRaises(ValueError):
                output.public_durable_delivery(json.dumps(dict(row,failed_child_inputs_completed=completed,failed_child_inputs_expected=expected)))
        for changed in (dict(row,root_cleanup='retained'),dict(row,root_cleanup='unverified'),dict(row,result='passed'),dict(row,first_failure=None),dict(row,producer_reaped=False),dict(row,producer_group_absent=False)):
            with self.assertRaises(ValueError):output.public_durable_delivery(json.dumps(changed))
        fallback=dict(row,first_outcome=None,failed_child_inputs_completed=None,failed_child_inputs_expected=None)
        self.assertEqual(output.public_durable_delivery(json.dumps(fallback)),fallback)
        with self.assertRaises(ValueError):
            output.public_durable_delivery(json.dumps(row)[:-1]+',"first_outcome":"HostPermission"}')
        with self.assertRaises(ValueError):
            output.public_durable_delivery(json.dumps(dict(row,schema=2)))
    def test_export_predicates_and_recipient_lower_sites_are_closed_without_schema_growth(self):
        sites=(
            'ExportProofCurrent',
            'ExportProofOrigin',
            'ExportSourceBefore',
            'ExportSourceAfter',
            'ExportMetadataOrigin',
            'ExportMarker',
            'ExportHistory',
            'ExportMaterialCeilings',
            'ExportIntake',
            'ExportVerifiedProof',
            'ExportRoster',
            'ExportPayload',
            'ExportOutputActions',
            'ExportRecipientBinding',
            'ExportSources',
            'ExportCheckpointScope',
            'ExportProofPermission',
            'ExportPermission',
            'ExportReplayScope',
            'ExportCommand',
            'ExportReplayLookup',
            'ExportDelta',
            'ExportEntry',
            'RecipientMutex',
            'RecipientDeadline',
            'RecipientOrigin',
            'RecipientObserverClone',
            'RecipientWriteSerialize',
            'RecipientWriteLimit',
            'RecipientWriteDeadline',
            'RecipientWriteTimeout',
            'RecipientWriteIo',
            'RecipientWriteEmpty',
            'RecipientFrame',
            'RecipientResponseDecode',
            'RecipientResponseDigest',
            'RecipientResponse',
            'SourceScopePredicate',
            'ProofRolePredicate',
            'MaterialActionPredicate',
            'MaterialScopePredicate',
            'ExportScopePredicate',
        )
        self.assertEqual(len(sites),42)
        self.assertEqual(len(set(sites)),42)
        source=(ROOT/'crates/wholepact-native-host/src/host/financial/durable_delivery_admission_v2.rs').read_text()
        body=re.search(r'enum DeliveryObservationSiteV2\s*\{(.*?)\n\}',source,re.S).group(1)
        actual={name.strip() for name in body.split(',') if name.strip()}
        original={'SourceOpen','SourceInspection','SourcePlan','RecipientPrepare','ExportPreview','ExportApproval','ExportCommit','ExportPostcheck','NativeCheck','SourceCheck','FixedRead'}
        semantic_internal={'PreparationSourceBefore','PreparationSourceAfter','PreparationApproval','HistoricalApprovalDeadline','HistoricalApprovalForeground','OriginalDisclosureSelector','MaterialRestrictionCapture','PairConfirmation'}
        self.assertEqual(actual,original|set(sites)|semantic_internal)
        qualification=(ROOT/'crates/wholepact-native-host/src/host/manual_enrollment/command/roster_publication_v2/sequential_construction_v3_qualification/durable_proposal_v1/delivery_admission_v2.rs').read_text()
        for exact in (
            'S::PreparationSourceBefore | S::PreparationSourceAfter => B::DeliverySourceCheck,',
            'S::PreparationApproval | S::HistoricalApprovalDeadline | S::HistoricalApprovalForeground => B::DeliveryNativeCheck,',
            'S::OriginalDisclosureSelector => B::DeliveryExportPreview,',
            'S::MaterialRestrictionCapture | S::PairConfirmation => B::DeliveryRecipientPrepare,',
        ):self.assertIn(exact,qualification)
        for site in semantic_internal:
            self.assertNotIn('Delivery'+site,output.DURABLE_DELIVERY_BOUNDARIES)
            with self.assertRaises(ValueError):
                output.public_durable_delivery(json.dumps(dict(self.record(),result='failed',first_failure='Delivery'+site,first_outcome='PredicateDenied')))
        for site in sites:
            boundary='Delivery'+site
            self.assertIn(boundary,output.DURABLE_DELIVERY_BOUNDARIES)
            outcome='PredicateDenied' if site.endswith('Predicate') else ('BridgePermission' if site.startswith('Recipient') else 'EngineDisclosureDenied')
            row=dict(self.record(),result='failed',first_failure=boundary,first_outcome=outcome,
                     failed_child_inputs_completed=111,failed_child_inputs_expected=117,
                     admission_count='unverified')
            self.assertEqual(output.public_durable_delivery(json.dumps(row)),row)
            self.assertEqual(row['schema'],4)
            self.assertEqual(len(row),28)
            self.assertFalse(row['authorization_allowed'])
        row=dict(self.record(),result='failed',first_failure='DeliveryRecipientFrame',first_outcome='OriginAuthentication')
        self.assertEqual(output.public_durable_delivery(json.dumps(row)),row)
        for bad in (dict(row,first_failure='DeliveryRecipientPrivatePath'),dict(row,first_outcome='private peer message'),dict(row,elapsed_ms=120001)):
            with self.assertRaises(ValueError):output.public_durable_delivery(json.dumps(bad))
    def test_receiver_stage_inventory_and_finite_outcomes_are_exact(self):
        stages=(
            'DeliveryReceiveNativeDeadline',
            'DeliveryReceiveRequest',
            'DeliveryReceiveSource',
            'DeliveryReceiveOriginalHistory',
            'DeliveryReceiveOriginalBinding',
            'DeliveryReceiveCurrentHistory',
            'DeliveryReceiveRedisclosureBinding',
            'DeliveryReceiveRecipientBinding',
            'DeliveryReceiveViewingKey',
            'DeliveryReceiveMaterialOwner',
            'DeliveryReceiveLease',
            'DeliveryReceiveNativeOrigin',
            'DeliveryReceiveSourceUnderLease',
            'DeliveryReceiveReceipts',
            'DeliveryReceiveProposal',
            'DeliveryReceiveAccount',
            'DeliveryReceiveAccountBinding',
            'DeliveryReceiveReviewerScope',
            'DeliveryReceiveDeadline',
            'DeliveryReceiveOriginalSource',
            'DeliveryReceivePeer',
            'DeliveryReceiveMaterialClock',
            'DeliveryReceiveMaterialScope',
            'DeliveryReceiveRequestDigest',
            'DeliveryReceiveReadyWrite',
            'DeliveryReceiveFrame',
            'DeliveryReceiveCommandParse',
            'DeliveryReceiveCommandBinding',
            'DeliveryReceivePayloadLimit',
            'DeliveryReceiveChunkDecode',
            'DeliveryReceiveCurrentWrite',
            'DeliveryReceiveReceivingWrite',
            'DeliveryReceivePayloadBinding',
            'DeliveryReceivePayloadParse',
            'DeliveryReceivePayloadCanonical',
            'DeliveryReceiveContributionBinding',
            'DeliveryReceiveUnsignedDecode',
            'DeliveryReceiveProvedDecode',
            'DeliveryReceiveEconomics',
            'DeliveryReceiveFinalBinding',
            'DeliveryReceiveFinalSource',
            'DeliveryReceiveFinalPeer',
            'DeliveryReceiveFinalDeadline',
            'DeliveryReceiveFinalMaterialClock',
            'DeliveryReceiveFinalMaterialScope',
            'DeliveryReceiveImportedWrite',
            'DeliveryReceiveTerminal',
        )
        additions=(
            'JournalExpired',
            'JournalPermission',
            'JournalOther',
            'ConstructionInvalid',
            'ConstructionBinding',
            'ConstructionStale',
            'ConstructionStorage',
            'ConstructionSync',
        )
        source=(ROOT/'crates/wholepact-signer/src/native_ui/runtime/durable_delivery_admission_v2.rs').read_text()
        receiver=source.split('mod receiver_diagnostics_v2 {',1)[1]
        def labels(name):
            body=re.search(r'labels!\s*\{\s*'+name+r'\s*\{(.*?)\}\s*\}',receiver,re.S).group(1)
            values=re.findall(r'\b([A-Za-z][A-Za-z0-9_]*)\s*,',body)
            self.assertEqual(len(values),len(set(values)))
            return values
        self.assertEqual(labels('Stage'),list(stages))
        self.assertEqual(len(stages),47)
        self.assertEqual(set(stages),{name for name in output.DURABLE_DELIVERY_BOUNDARIES if name.startswith('DeliveryReceive')})
        self.assertEqual(set(stages),{name for name in output.BOUNDARIES if name.startswith('DeliveryReceive')})
        outcomes=labels('Outcome')
        self.assertEqual(len(additions),8)
        self.assertEqual(set(additions),{name for name in outcomes if name.startswith(('Journal','Construction'))})
        self.assertTrue(set(outcomes)<=output.OUTCOMES)
        for stage in stages:
            row=dict(self.record(),result='failed',first_failure=stage,first_outcome='WorkerFailure',admission_count='unverified')
            self.assertEqual(output.public_durable_delivery(json.dumps(row)),row)
        # This establishes closed wire vocabulary, not per-site runtime causes.
        for outcome in additions:
            row=dict(self.record(),result='failed',first_failure='DeliveryReceiveTerminal',first_outcome=outcome,admission_count='unverified')
            self.assertEqual(output.public_durable_delivery(json.dumps(row)),row)

    def test_admission_observation_source_and_public_vocabularies_agree(self):
        # Closed vocabulary validation, not evidence of an admitted operation.
        stages = (
            'RetainedBinding',
            'BeforeSendChannel',
            'BeforeSendSource',
            'BeforeWriteChannel',
            'WriteFrame',
            'WritePrecheck',
            'WriteIo',
            'WritePostcheck',
            'FlushPrecheck',
            'FlushIo',
            'FlushPostcheck',
            'AfterWriteSource',
            'AfterWriteChannel',
            'ReadFrame',
            'ReadPrecheck',
            'ReadIo',
            'ReadPostcheck',
            'AfterReadSource',
            'AfterReadChannel',
            'ResponseRejected',
            'ResponseVariant',
            'Snapshot',
            'CommittedHead',
        )
        io_kinds = (
            'TimedOut',
            'WouldBlock',
            'Interrupted',
            'UnexpectedEof',
            'WriteZero',
            'ConnectionAborted',
            'ConnectionRefused',
            'ConnectionReset',
            'BrokenPipe',
            'NotConnected',
            'PermissionDenied',
            'InvalidData',
            'InvalidInput',
            'Other',
        )
        authority = (ROOT/'crates/wholepact-authority/src/transport/durable_delivery_admission_v3.rs').read_text()
        for name, expected in (('AdmissionFailureStageV3', stages), ('AdmissionIoKindV3', io_kinds)):
            body = re.search(r'pub enum '+name+r'\s*\{(.*?)\n\}', authority, re.S).group(1)
            actual = re.findall(r'^\s+(\w+),$', body, re.M)
            self.assertEqual(actual, list(expected))
            self.assertEqual(len(actual), len(set(actual)))
        signer = (ROOT/'crates/wholepact-signer/src/native_ui/runtime.rs').read_text().split('pub(super) mod delivery_diagnostics_v2 {', 1)[1]
        signer = signer.split('    #[cfg(test)]', 1)[0]
        stage_body = re.search(r'labels!\s*\{\s*Stage\s*\{(.*?)\}\s*\}', signer, re.S).group(1)
        outcome_body = re.search(r'labels!\s*\{\s*Outcome\s*\{(.*?)\}\s*\}', signer, re.S).group(1)
        expected_stages = {'DeliveryAdmission'+stage for stage in stages}
        expected_io = {'AuthorityIo'+kind for kind in io_kinds}
        self.assertEqual(expected_stages, set(re.findall(r'\bDeliveryAdmission\w+', stage_body)))
        self.assertEqual(expected_io, set(re.findall(r'\bAuthorityIo\w+', outcome_body)))
        self.assertEqual(expected_stages, {stage for stage in output.DURABLE_DELIVERY_BOUNDARIES if stage.startswith('DeliveryAdmission')})
        self.assertEqual(expected_io, {value for value in output.OUTCOMES if value.startswith('AuthorityIo')})
        self.assertTrue(expected_stages.isdisjoint(output.DURABLE_DELIVERY_RETAINED_EXPORTER_BOUNDARIES))

    def test_admission_observation_passes_bounded_projection_without_commit_claim(self):
        # Exercise real bounded-line parsing and final public projection. These
        # records describe failed attempts; they do not establish commit absence.
        cases = (
            ('DeliveryAdmissionWriteIo', 'AuthorityIoBrokenPipe'),
            ('DeliveryAdmissionReadIo', 'AuthorityIoUnexpectedEof'),
            ('DeliveryAdmissionFlushPostcheck', 'SignerLocked'),
            ('DeliveryAdmissionResponseRejected', 'AuthorityPolicyDenied'),
            ('DeliveryAdmissionResponseVariant', 'PredicateDenied'),
            ('DeliveryAdmissionCommittedHead', 'AuthorityInvalidBinding'),
        )
        for stage, outcome in cases:
            row = dict(self.record(), result='failed', first_failure=stage,
                       first_outcome=outcome, admission_count='unverified',
                       failed_child_inputs_completed=113, failed_child_inputs_expected=121,
                       reader_exit='not_started', reader_reaped=False,
                       reader_group_absent=False, reader_no_effects_verified=False)
            encoded = self.line(row).encode('ascii')
            parser = output.BoundedLines('exact')
            self.assertEqual(parser.feed(encoded[:17]), [])
            self.assertEqual(parser.feed(encoded[17:]+b'\n'), [encoded])
            self.assertEqual(output.public_line(encoded, 'exact'), ('durable_delivery', row))
            self.assertEqual(len(row), 28)
            self.assertEqual(row['schema'], 4)
            self.assertLess(len(encoded), 2048)
            self.assertFalse(row['authorization_allowed'])
            self.assertNotIn('commit_absent', row)
            for bad in (dict(row, first_outcome='private IO error text'),
                        dict(row, first_failure='DeliveryAdmissionPrivatePeer'),
                        dict(row, producer_reaped=False),
                        dict(row, root_cleanup='retained'),
                        dict(row, result='passed')):
                with self.assertRaises(ValueError):
                    output.public_line(self.line(bad).encode('ascii'), 'exact')

    def test_actual_frame_cause_vocabulary_keeps_schema_and_ambiguity(self):
        causes = (
            'Unclassified', 'Deadline', 'Eof', 'CredentialsMissing',
            'CredentialsMismatch', 'AncillaryRejected', 'Truncated',
            'PeerNotLive', 'CurrentCheck', 'Io', 'Limit', 'InvalidFrame',
            'InvalidBudget',
        )
        labels = {'OriginFrame' + cause for cause in causes}
        self.assertEqual(len(labels), 13)
        self.assertEqual(labels, {item for item in output.OUTCOMES if item.startswith('OriginFrame')})
        for boundary in ('DeliveryReceiveFrame', 'DeliveryRecipientFrame'):
            for outcome in labels:
                row = dict(self.record(), result='failed', first_failure=boundary,
                           first_outcome=outcome, admission_count='unverified')
                self.assertEqual(output.public_durable_delivery(json.dumps(row)), row)
                self.assertEqual(len(row), 28)
                self.assertFalse(row['authorization_allowed'])
        for outcome in ('OriginFrameGuessedExpiry', 'OriginFramePrivatePeer'):
            row = dict(self.record(), result='failed', first_failure='DeliveryReceiveFrame',
                       first_outcome=outcome, admission_count='unverified')
            with self.assertRaises(ValueError):
                output.public_durable_delivery(json.dumps(row))

    def test_receiver_failure_projection_preserves_limits_and_no_effect_inference(self):
        for stage,outcome in (('DeliveryReceiveDeadline','PredicateDenied'),
                              ('DeliveryReceiveReceipts','JournalExpired'),
                              ('DeliveryReceiveMaterialScope','ConstructionStale'),
                              ('DeliveryReceiveFrame','OriginAuthentication'),
                              ('DeliveryReceiveSource','SignerLocked')):
            row=dict(self.record(),result='failed',first_failure=stage,first_outcome=outcome,
                     failed_child_inputs_completed=113,failed_child_inputs_expected=121,
                     admission_count='unverified',reader_exit='not_started',reader_reaped=False,
                     reader_group_absent=False,reader_no_effects_verified=False)
            self.assertEqual(output.public_durable_delivery(json.dumps(row)),row)
            self.assertEqual(row['schema'],4)
            self.assertEqual(len(row),28)
            self.assertLess(len(self.line(row).encode()),2048)
            self.assertFalse(row['authorization_allowed'])
            self.assertNotIn('no_effects',row)
            for changed in (dict(row,first_failure='DeliveryReceivePrivatePath'),
                            dict(row,first_outcome='private source error'),dict(row,elapsed_ms=120001),
                            dict(row,root_cleanup='retained'),dict(row,producer_reaped=False)):
                with self.assertRaises(ValueError):output.public_durable_delivery(json.dumps(changed))
    def test_export_unknown_is_observed_without_claiming_rollback_or_success(self):
        row=dict(self.record(),result='failed',first_failure='DeliveryExportCommit',
                 first_outcome='EngineDisclosureUnknown',admission_count='unverified')
        self.assertEqual(output.public_durable_delivery(json.dumps(row)),row)
        self.assertFalse(row['authorization_allowed'])
        self.assertNotIn('no_effects',row)
        self.assertLess(len(self.line(row).encode('utf8')),2048)
    def test_every_success_fact_is_required_and_partial_commit_is_not_success(self):
        row=self.record()
        for key in output.DURABLE_DELIVERY_BOOL_FIELDS:
            with self.assertRaises(ValueError):output.public_durable_delivery(json.dumps(dict(row,**{key:False})))
        for key,value in (('admission_count','1_of_2'),('admission_count','unverified'),('producer_exit','other'),('reader_exit','not_started'),('root_cleanup','retained'),('first_failure','DeliveryNativeAdmission')):
            with self.assertRaises(ValueError):output.public_durable_delivery(json.dumps(dict(row,**{key:value})))
        for count in ('0_of_2','1_of_2','2_of_2','unverified'):
            failed=dict(row,result='failed',first_failure='DeliveryNativeAdmission',admission_count=count,reader_exit='not_started',reader_reaped=False,reader_group_absent=False)
            self.assertEqual(output.public_durable_delivery(json.dumps(failed)),failed)
    def test_fragmented_oversized_private_unknown_records_fail_closed(self):
        line=self.line().encode()
        for split in range(len(line)+1):
            parser=output.BoundedLines('exact')
            self.assertEqual(parser.feed(line[:split]),[])
            self.assertEqual(parser.feed(line[split:]+b'\n'),[line])
        self.assertEqual(output.public_line(b'test exact ... '+line,'exact'),('durable_delivery',self.record()))
        self.assertIsNone(output.public_line(b'private '+line,'exact'))
        for bad in (line[:-1],b'CI_SYNTHETIC_DURABLE_DELIVERY '+bytes([255]),b'CI_SYNTHETIC_DURABLE_DELIVERY_INVALID'):
            with self.assertRaises(ValueError):output.public_line(bad,'exact')
        parser=output.BoundedLines('exact')
        rows=parser.feed(b'CI_SYNTHETIC_DURABLE_DELIVERY '+b'x'*9000+b'\n'+line+b'\n')
        self.assertEqual(rows[0],output.DURABLE_DELIVERY_INVALID.encode())
        with self.assertRaises(ValueError):output.public_line(rows[0],'exact')
    def test_real_run_projection_requires_aggregate_cleanup_and_one_exact_result(self):
        run=lambda rows,status=0,phase='durable-delivery-admission':PrivateWorkspaceOutputTests().run_fake(rows,status,phase)
        text=run([self.line()])
        self.assertIn('phase=durable-delivery-admission passed=true cleanup_verified=true',text)
        self.assertEqual(text.count(output.DURABLE_DELIVERY_PREFIX),1)
        with self.assertRaises(RuntimeError):run([])
        with self.assertRaises(RuntimeError):run([self.line()],101)
        with self.assertRaises(ValueError):run([self.line(),self.line()])
        with self.assertRaises(ValueError):run([self.line()],phase='durable-private-reopen')
        with self.assertRaises(ValueError):run([PrivateWorkspaceOutputTests().line()])
        cleanup='[JOINED_CLEANUP group_signal=AlreadyAbsentWhileLeaderOwned group_absence=OriginalGroupAbsentObserved direct_child=Reaped root_cleanup=ClosedAndAbsenceVerified exit=Some(0) signal=None core_dumped=false]'
        with self.assertRaises(ValueError):run([cleanup,self.line()])


class DurableDeliveryRetainedExporterOutputTests(unittest.TestCase):
    """Schema/parser checks only, not evidence of native delivery or causality."""
    exporter_boundaries=(
        'DeliveryExportProofCurrent',
        'DeliveryExportProofOrigin',
        'DeliveryExportSourceBefore',
        'DeliveryExportSourceAfter',
        'DeliveryExportMetadataOrigin',
        'DeliveryExportMarker',
        'DeliveryExportHistory',
        'DeliveryExportMaterialCeilings',
        'DeliveryExportIntake',
        'DeliveryExportVerifiedProof',
        'DeliveryExportRoster',
        'DeliveryExportPayload',
        'DeliveryExportOutputActions',
        'DeliveryExportRecipientBinding',
        'DeliveryExportSources',
        'DeliveryExportCheckpointScope',
        'DeliveryExportProofPermission',
        'DeliveryExportPermission',
        'DeliveryExportReplayScope',
        'DeliveryExportCommand',
        'DeliveryExportReplayLookup',
        'DeliveryExportDelta',
        'DeliveryExportEntry',
        'DeliveryRecipientMutex',
        'DeliveryRecipientDeadline',
        'DeliveryRecipientOrigin',
        'DeliveryRecipientObserverClone',
        'DeliveryRecipientWriteSerialize',
        'DeliveryRecipientWriteLimit',
        'DeliveryRecipientWriteDeadline',
        'DeliveryRecipientWriteTimeout',
        'DeliveryRecipientWriteIo',
        'DeliveryRecipientWriteEmpty',
        'DeliveryRecipientFrame',
        'DeliveryRecipientResponseDecode',
        'DeliveryRecipientResponseDigest',
        'DeliveryRecipientResponse',
        'DeliverySourceScopePredicate',
        'DeliveryProofRolePredicate',
        'DeliveryMaterialActionPredicate',
        'DeliveryMaterialScopePredicate',
        'DeliveryExportScopePredicate',
        'DeliveryNativeCheck',
        'DeliverySourceCheck',
    )

    def record(self):
        return dict(DurableDeliveryOutputTests().record(),result='failed',
                    first_failure='DeliveryReceiveFrame',first_outcome='OriginAuthentication',
                    retained_exporter_failure='DeliveryExportPermission',
                    retained_exporter_outcome='EngineDisclosureDenied',
                    failed_child_inputs_completed=113,failed_child_inputs_expected=121,
                    admission_count='unverified',reader_exit='not_started',reader_reaped=False,
                    reader_group_absent=False,reader_no_effects_verified=False)

    def test_schema4_has_exact28_fields_and_required_nullable_pair(self):
        expected=frozenset((
            'schema','phase','result','first_failure','first_outcome',
            'retained_exporter_failure','retained_exporter_outcome',
            'failed_child_inputs_completed','failed_child_inputs_expected',
            'producer_exit','producer_reaped','producer_group_absent',
            'reader_exit','reader_reaped','reader_group_absent','root_cleanup',
            'admission_count','fixed_verified','exact_fixed_prefix_preserved',
            'exact_export_history_preserved','exact_original_scopes_preserved',
            'exact_original_intents_preserved','authenticated_histories_verified',
            'unsupported_actions_denied','reader_no_effects_verified',
            'authorization_allowed','distribution_allowed','public_chain_verified',
        ))
        self.assertEqual(len(expected),28)
        self.assertEqual(output.DURABLE_DELIVERY_FIELDS,expected)
        row=self.record()
        self.assertEqual(set(row),expected)
        self.assertEqual(row['schema'],4)
        for fields in (('retained_exporter_failure',),('retained_exporter_outcome',),
                       ('retained_exporter_failure','retained_exporter_outcome')):
            missing=row.copy()
            for field in fields: missing.pop(field)
            with self.assertRaises(ValueError): output.public_durable_delivery(json.dumps(missing))
        nulls=dict(row,retained_exporter_failure=None,retained_exporter_outcome=None)
        self.assertEqual(output.public_durable_delivery(json.dumps(nulls)),nulls)
        source=(ROOT/'crates/wholepact-native-host/src/host/manual_enrollment/command/roster_publication_v2/sequential_construction_v3_qualification/durable_proposal_v1/delivery_admission_v2.rs').read_text()
        fields=re.search(r'struct PublicOutcomeV4\s*\{(.*?)\n\}',source,re.S).group(1)
        for field in ('retained_exporter_failure','retained_exporter_outcome'):
            self.assertRegex(fields,r'#\[serde\(deserialize_with = "required_nullable"\)\]\s*'+field+r': Option<String>,')

    def test_exact44_exporter_boundary_inventory_matches_rust_without_vocabulary_growth(self):
        self.assertEqual(len(self.exporter_boundaries),44)
        self.assertEqual(len(set(self.exporter_boundaries)),44)
        self.assertEqual(output.DURABLE_DELIVERY_RETAINED_EXPORTER_BOUNDARIES,
                         frozenset(self.exporter_boundaries))
        self.assertTrue(set(self.exporter_boundaries)<=output.DURABLE_DELIVERY_BOUNDARIES)
        source=(ROOT/'crates/wholepact-native-host/src/host/manual_enrollment/command/roster_publication_v2/sequential_construction_v3_qualification/durable_proposal_v1/delivery_admission_v2.rs').read_text()
        body=re.search(r'const RETAINED_EXPORTER_BOUNDARIES: &\[&str\] = &\[(.*?)\];',source,re.S).group(1)
        labels=re.findall(r'"(\w+)"',body)
        self.assertEqual(len(labels),44)
        self.assertEqual(set(labels),set(self.exporter_boundaries))
        self.assertTrue(set(labels).isdisjoint(name for name in output.DURABLE_DELIVERY_BOUNDARIES
                                             if name.startswith(('DeliveryReceive','DeliveryRedisclosure'))))

    def test_every_retained_boundary_and_terminal_outcome_preserves_original_pair(self):
        original=self.record()
        terminal=output.OUTCOMES-{'Begin','Complete'}
        for field,values in (('retained_exporter_failure',self.exporter_boundaries),
                             ('retained_exporter_outcome',terminal)):
            for value in values:
                row=dict(original,**{field:value})
                parsed=output.public_durable_delivery(json.dumps(row))
                self.assertEqual(parsed,row)
                self.assertEqual((parsed['first_failure'],parsed['first_outcome']),
                                 ('DeliveryReceiveFrame','OriginAuthentication'))
                self.assertFalse(parsed['reader_no_effects_verified'])
                self.assertTrue(all(parsed[key] is False for key in output.DURABLE_DELIVERY_FALSE_FIELDS))
        # The existing original outcome stays independently nullable. Neither
        # pair asserts first-ever ordering, cause, rollback or exposure absence.
        row=dict(original,first_outcome=None)
        self.assertEqual(output.public_durable_delivery(json.dumps(row)),row)

    def test_retained_pair_rejects_partial_malformed_private_wrapper_and_receiver_values(self):
        row=self.record()
        bad_boundaries=(None,'','private/source/path','DeliveryReceiveFrame',
                        'DeliveryRedisclosureServe','DeliveryExportCommit','DeliverySourceExport',
                        'DeliveryRecipientPrepare','PrivateWorkspaceRootCleanup',
                        'DeliveryExportPermission private',0,True,[],{},['DeliveryExportPermission'])
        bad_outcomes=(None,'','Begin','Complete','private peer message','EngineDisclosureDenied private',
                      0,True,[],{},['EngineDisclosureDenied'])
        for field,values in (('retained_exporter_failure',bad_boundaries),
                             ('retained_exporter_outcome',bad_outcomes)):
            for value in values:
                with self.assertRaises(ValueError):
                    output.public_durable_delivery(json.dumps(dict(row,**{field:value})))
        text=json.dumps(row,separators=(',',':'))
        for field in ('retained_exporter_failure','retained_exporter_outcome'):
            duplicate=text[:-1]+',"'+field+'":null}'
            with self.assertRaises(ValueError): output.public_durable_delivery(duplicate)
        for key in ('retained_exporter_private','retained_exporter_elapsed_ms','no_effects'):
            with self.assertRaises(ValueError):
                output.public_durable_delivery(json.dumps(dict(row,**{key:'private'})))

    def test_nonnull_retained_pair_requires_original_failure_and_existing_input_progress(self):
        row=self.record()
        for changes in (dict(first_failure=None),
                        dict(failed_child_inputs_completed=None,failed_child_inputs_expected=None),
                        dict(failed_child_inputs_completed=None),dict(failed_child_inputs_expected=None),
                        dict(failed_child_inputs_completed=True),dict(failed_child_inputs_expected=False),
                        dict(failed_child_inputs_completed=-1),dict(failed_child_inputs_completed=122),
                        dict(failed_child_inputs_expected=513),
                        dict(failed_child_inputs_completed=0,failed_child_inputs_expected=0)):
            with self.assertRaises(ValueError):
                output.public_durable_delivery(json.dumps(dict(row,**changes)))
        for completed,expected in ((0,1),(512,512)):
            valid=dict(row,failed_child_inputs_completed=completed,failed_child_inputs_expected=expected)
            self.assertEqual(output.public_durable_delivery(json.dumps(valid)),valid)

    def test_retained_observation_uses_existing_failure_and_verified_cleanup_gate(self):
        row=self.record()
        for changes in (dict(root_cleanup='retained'),dict(root_cleanup='unverified'),
                        dict(producer_reaped=False),dict(producer_group_absent=False),
                        dict(result='passed')):
            with self.assertRaises(ValueError):
                output.public_durable_delivery(json.dumps(dict(row,**changes)))
        absent=dict(row,first_outcome=None,failed_child_inputs_completed=None,
                    failed_child_inputs_expected=None,retained_exporter_failure=None,
                    retained_exporter_outcome=None)
        for changes in (dict(root_cleanup='retained'),dict(root_cleanup='unverified'),
                        dict(producer_reaped=False),dict(producer_group_absent=False)):
            withheld=dict(absent,**changes)
            self.assertEqual(output.public_durable_delivery(json.dumps(withheld)),withheld)
        # The producer-side observation does not invent a reader cleanup gate.
        self.assertEqual(output.public_durable_delivery(json.dumps(row)),row)
        reader_failed=dict(row,reader_exit='other',reader_reaped=True,reader_group_absent=True)
        self.assertEqual(output.public_durable_delivery(json.dumps(reader_failed)),reader_failed)

    def test_success_requires_both_retained_fields_null_and_old_schemas_refuse(self):
        success=DurableDeliveryOutputTests().record()
        self.assertEqual(output.public_durable_delivery(json.dumps(success)),success)
        for changes in (dict(retained_exporter_failure='DeliveryNativeCheck'),
                        dict(retained_exporter_outcome='HostPermission'),
                        dict(retained_exporter_failure='DeliveryNativeCheck',retained_exporter_outcome='HostPermission')):
            with self.assertRaises(ValueError):
                output.public_durable_delivery(json.dumps(dict(success,**changes)))
        for schema in (1,2,3,True,4.0,'4',None):
            with self.assertRaises(ValueError):
                output.public_durable_delivery(json.dumps(dict(self.record(),schema=schema)))
        legacy=dict(success,schema=3)
        del legacy['retained_exporter_failure']; del legacy['retained_exporter_outcome']
        self.assertEqual(len(legacy),26)
        with self.assertRaises(ValueError): output.public_durable_delivery(json.dumps(legacy))

    def test_retained_pair_keeps_exact2048_byte_cap_and_existing_public_framing(self):
        row=self.record()
        row.update(retained_exporter_failure=max(self.exporter_boundaries,key=len),
                   retained_exporter_outcome=max(output.OUTCOMES-{'Begin','Complete'},key=len),
                   failed_child_inputs_completed=512,failed_child_inputs_expected=512)
        text=json.dumps(row,separators=(',',':'))
        self.assertLess(len(text.encode('utf8')),2048)
        at_limit=text+' '*(2048-len(text.encode('utf8')))
        self.assertEqual(output.public_durable_delivery(at_limit),row)
        with self.assertRaises(ValueError): output.public_durable_delivery(at_limit+' ')
        line=(output.DURABLE_DELIVERY_PREFIX+text).encode('utf8')
        self.assertEqual(output.public_line(line,'exact'),('durable_delivery',row))
        self.assertEqual(output.public_line(b'test exact ... '+line,'exact'),('durable_delivery',row))
        self.assertIsNone(output.public_line(b'private '+line,'exact'))
        with self.assertRaises(ValueError): output.public_line(line[:-1],'exact')


if __name__=='__main__':
    unittest.main()
