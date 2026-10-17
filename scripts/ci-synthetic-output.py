#!/usr/bin/env python3
"""Bounded, public-only output for two fixed synthetic test selections.

Unknown runtime text is discarded, never written to a log. Outer timeout cannot
establish descendant cleanup; the Rust owner is the actual cleanup producer.
"""
import json
import os
import pathlib
import re
import resource
import select
import subprocess
import sys
import time

PREFIX = 'host::manual_enrollment::command::roster_publication_v2::sequential_construction_v3::qualification::'
TESTS = {
    'initial': (PREFIX + 'initial_joined_v3::actual_three_born_initial_roster_publications_preserve_refusal', 300),
    'full': (PREFIX + 'full_payment_inputs_v1::actual_three_born_full_payment_uses_one_original_synthetic_path', 1080),
}
PURE_TESTS = tuple(PREFIX + suffix for suffix in (
    'owned_test_process_group_v1::pure_tests::pure_cleanup_orders_one_signal_before_reap_then_only_observation',
    'owned_test_process_group_v1::pure_tests::pure_cleanup_never_observes_or_resignals_after_failed_or_expired_reap',
    'owned_test_process_group_v1::pure_tests::pure_cleanup_uncertain_or_reused_group_is_not_success',
    'owned_test_process_group_v1::pure_tests::pure_cleanup_does_not_hide_an_unverified_signal',
    'owned_test_process_group_v1::pure_tests::pure_cleanup_lost_child_ownership_never_signals_numeric_group',
    'owned_test_process_group_v1::pure_tests::pure_wait_policy_requires_default_without_automatic_reaping',
    'owned_test_process_group_v1::pure_tests::pure_unsupported_or_unknown_wait_policy_never_calls_spawn',
    'owned_test_process_group_v1::pure_tests::pure_live_child_with_unsafe_or_unknown_policy_never_signals_and_retains_root',
    'synthetic_provider_tls_v1::owned_tls_child_v1::pure_tests::pure_tls_original_preparation_cutoff_is_not_cleanup_grace',
    'synthetic_provider_tls_v1::owned_tls_child_v1::pure_tests::pure_tls_stop_plan_never_signals_missing_or_auto_reaped_anchor',
    'synthetic_provider_tls_v1::owned_tls_child_v1::pure_tests::pure_tls_exited_child_needs_only_exact_reap_never_a_signal',
    'process_containment_v1::pure_tests::pure_core_limit_requires_known_zero',
    'process_containment_v1::pure_tests::pure_core_route_has_only_file_pipe_or_unknown_classification',
    'public_outcome_v1::tests::public_outcome_allowlist_maps_exact_values_without_upstream_identifiers',
    'public_outcome_v1::tests::public_outcome_refuses_mismatched_or_claimed_real_success',
    'public_outcome_v1::tests::public_outcome_parser_denies_unknown_truncated_and_noncanonical_records',
    'public_outcome_v1::tests::public_outcome_sidecar_is_single_create_exact_bounded_and_private',
    'public_outcome_v1::tests::public_outcome_sidecar_denies_symlink_multilink_partial_and_oversize',
))
POLICY_ENVELOPE_TESTS = tuple(PREFIX + 'retained_joined_v3::original_policy_export_v2::tests::' + name for name in (
    'producer_shaped_policy_envelope_projects_only_validated_original',
    'policy_envelope_rejects_individually_valid_substituted_originals',
    'policy_envelope_refuses_bare_legacy_unknown_and_duplicate_fields',
))
PROMPT_RENDERING_TESTS = tuple(PREFIX + name for name in (
    'finite_prompt_rendering_preserves_exact_terminal_purpose',
    'full_finite_prompt_census_uses_only_exact_rendered_expectations',
))
STORAGE_BOOTSTRAP_TEST = 'recovery_generation::layered::tests::native_layered_current_eight_nine_parent_provenance_is_exact_and_not_relabelable'
MARKER = 'WHOLEPACT_SYNTHETIC_PUBLIC_OUTCOME_V1='
CORE = re.compile(r'\[JOINED_CORE_POLICY inherited_limit=Zero collector=(File|Pipe|Unknown) process_dumpability=Unchanged crash_copy_absence_verified=false\]')
OPTION_INT = r'(?:None|Some\((?:0|[1-9][0-9]{0,9})\))'
CLEANUP = re.compile(r'\[JOINED_CLEANUP group_signal=(SentWhileLeaderOwned|AlreadyAbsentWhileLeaderOwned|Unverified) group_absence=(OriginalGroupAbsentObserved|Unverified) direct_child=(Reaped|Unverified) root_cleanup=(ClosedAndAbsenceVerified|RetainedForUnverifiedProcess|CloseOrAbsenceUnverified) exit=(' + OPTION_INT + r') signal=(' + OPTION_INT + r') core_dumped=(true|false)\]')
FAILURE = re.compile(r'\[JOINED_FAILURE exit=(' + OPTION_INT + r') signal=(' + OPTION_INT + r') core_dumped=(true|false) inputs=(0|[1-9][0-9]{0,5})/(0|[1-9][0-9]{0,5}) static_boundaries=([^\]\r\n]+)\]')
# Exact closed labels copied from the same compiled safe_diagnostics_v1.rs.
# The no-process self-tests check equality with those original Rust declarations.
BOUNDARIES = frozenset('Bootstrap Session PublicRefusal PaymentReceiver AgreementInput AgreementNative WitnessSetup WitnessOrigin SignerStart BirthExport BirthRead BirthEnroll BirthHistory BirthAcknowledge BirthDistinct SinglePrepare SingleOpen SinglePair SingleSubmit SingleExport SingleWitness SinglePublicationPrepare SingleHistory SinglePublicationOpen SinglePublicationPair SingleFinish SingleClose RosterPrepare RosterOpen RosterPair RosterSubmit RosterExport RosterWitness RosterPublicationPrepare RosterHistory RosterPublicationOpen RosterPublicationPair RosterFinish RosterClose MetadataCheck FinancialRefusal EndInvariant SignerCreate SignerExportBirth SignerAcknowledge SignerOpenSingleIntent SignerPollSingleIntent SignerExportSingle SignerOpenSinglePublication SignerPollSinglePublication SignerCloseSinglePublication SignerOpenRosterIntent SignerPollRosterIntent SignerExportRoster SignerOpenRosterPublication SignerPollRosterPublication SignerCloseRosterPublication SignerOpenContinuationIntent SignerPollContinuationIntent SignerOpenContinuedPublication SignerPollContinuedPublication SignerCloseContinuedPublication SignerExportOriginalFullPlan SignerOpenCommonContextRead SignerPollCommonContextRead SignerParkCommonContextCompletion SignerPeerMetadata SignerNativeEntry SignerEndpoint SignerProvider SignerDeadline SignerSingleController ObservedInputs ObservedRetainedPredecessor ObservedAssemble ObservedCandidateReview ObservedPlanExport ObservedPlanSign ObservedPlanRead ObservedPlanAuthenticate ObservedPlanWitness ObservedContinuation ObservedOwnerSplit ObservedReadPrepare ObservedReadHistory ObservedReadOpen ObservedReadPair ObservedReadFinish ObservedReadPark ObservedBarrier ObservedProviderDrain ConstructedPredecessor ConstructedDisclosure ConstructedWitnessOriginal ConstructedWitnessGrant ConstructedWitnessScope ConstructedPendingFile ConstructedPendingReview ConstructedSignerOpen ConstructedConsume ConstructedSignerPark ConstructedServerSeal ConstructedCheckpoint ConstructedSavedOriginal ConstructedInvariant ConstructedProviderDrain SignerOpenOriginalCompletion SignerPollOriginalCompletion ProvedConstructionDrain ProvedOriginalJob ProvedOriginalCorrelation ProvedHostPublic ProvedWitnessKey ProvedNamedOpen ProvedNamedPair ProvedNamedStatus ProvedNamedRecords ProvedNamedProfile ProvedNativePins ProvedCarrierPrepare ProvedCarrierExport ProvedCarrierRecover ProvedCarrierRetained ProvedCarrierInvariant SignerOpenOriginalNamed SignerPollOriginalNamed SignerRetainOriginalProfile SignerNamedEnrollmentExport SignerNamedInstalledMetadata SignerNamedVerifierArm SignerNamedVerifierStart SignerNamedVerifierPoll SignerNamedAssertionExport SignerNamedOriginalImport SignerNamedOriginalSubmit SignerNamedOriginalSign SignerNamedHostServing FullPaymentPredecessor FullEnrollmentExport FullEnrollmentInstall FullArtifactsInstall FullInstalledMetadata FullVerifierRequest FullAssertion FullOriginalImport FullAdmission FullSignatureReturn FullHistory FullReturnIntake FullMerge FullCurrentDispatch FullRecipientReceipt SingleAccountUnlock SingleRetainedRead SingleAcquireState SingleAttemptedSource SingleAttemptsRead SingleRetainedReopen SinglePreacquire SingleReference SingleAccountId SingleAudit SingleEndpointCreate SingleDirectoryOpen SingleIpcBind SingleEndpointPublish SingleWorkOpen SingleWorkPrepareIntent SingleWorkPrepareSignature SingleWorkPrepareExport SingleWorkPrepareReentry SingleWorkPrepareWitness SingleWorkPrepareAcquire SingleWorkPrepareActivate SingleWorkPreparePublication SingleWorkPrepareServe SingleWorkCommitPair SingleWorkCommitRetain SingleWorkCommitSignature SingleWorkCommitExport SingleWorkCommitReentry SingleWorkCommitWitness SingleWorkCommitAcquire SingleWorkCommitActivate SingleWorkCommitAdmission SingleWorkCommitPublication SingleWorkCommitServe SingleWorkRetryAcquire SingleWorkRetryActivate SingleWorkRetryAdmission SingleWorkOther SingleWorkAdoptOutput FullOriginalPolicy RetainedPredecessor RetainedMaterial RetainedEconomics RetainedInvocation RetainedRuntime RetainedProvider RetainedTls RetainedWitness RetainedPolicyRead RetainedPolicyMatch RetainedSelectionFiles ContinuedPredecessor ContinuedObservation ContinuedOriginal ContinuedWait ContinuedPrepare'.split())
OUTCOMES = frozenset('Begin Complete HostPlatform HostTerminal HostPermission HostLocked HostInvalid HostAuthentication HostStorage HostQuarantined HostUnsupported HostReceipt HostRecoverySemantic HostRecoveryBackupUnsupported HostRecoveryFinancialUnsupported HostCompleteOriginRecoveryUnavailable HostHistoricalExportIncomplete HostGenerationArchiveIncomplete SignerUnavailable SignerPeerLifetimeUnavailable SignerIo SignerAuthentication SignerInvalidData SignerCrypto SignerLocked SignerBackupRequired SignerRecoveryRequired SignerAlreadyOpen SignerReviewMismatch SignerVerification SignerUncertain SignerConsentJournal SignerStore WorkerFailure'.split())
IO_KINDS = frozenset('NotFound PermissionDenied AlreadyExists InvalidInput InvalidData AddrInUse AddrNotAvailable WouldBlock TimedOut Interrupted Unsupported Other'.split())
FALSE_FIELDS = {'public_network_settlement_verified','public_network_inclusion_verified','independent_consensus_verified','attended_native_acceptance_verified','clears_authorization_exposure','permits_replacement'}
INT_FIELDS = {'schema','consensus_branch_id','expiry_height','submission_attempt','recipient_decrypted_zatoshis','recipient_owned_note_count','fabricated_inclusion_height','fabricated_tip_height','required_confirmations'}
STRING_FIELDS = {'evidence_kind','transaction_id','transaction_bytes_sha256','network','submission_outcome'}

def distinct_object(pairs):
    result={}
    for key,value in pairs:
        if key in result: raise ValueError('duplicate public field')
        result[key]=value
    return result

def public_outcome(text):
    if len(text.encode()) > 4096: raise ValueError('oversized public result')
    row=json.loads(text,object_pairs_hook=distinct_object)
    if not isinstance(row,dict) or set(row)!=FALSE_FIELDS|INT_FIELDS|STRING_FIELDS: raise ValueError('unexpected public fields')
    if any(row[k] is not False for k in FALSE_FIELDS): raise ValueError('stronger outcome claim')
    for key in INT_FIELDS:
        bits = 16 if key=='schema' else 64 if key=='recipient_decrypted_zatoshis' else 32
        if type(row[key]) is not int or not 0 < row[key] < 2**bits: raise ValueError('invalid public amount/count')
    if row['schema']!=1 or row['submission_attempt']!=1 or row['recipient_owned_note_count']!=1: raise ValueError('unexpected public version/attempt')
    if not 1 <= row['required_confirmations'] <= 32 or row['fabricated_tip_height']-row['fabricated_inclusion_height']+1 < row['required_confirmations']: raise ValueError('invalid fabricated confirmation')
    for key in ['transaction_id','transaction_bytes_sha256']:
        if type(row[key]) is not str or not re.fullmatch('[0-9a-f]{64}',row[key]): raise ValueError('invalid public digest')
    if row['evidence_kind']!='synthetic_full_payment_v1' or row['network']!='testnet' or row['submission_outcome']!='synthetic_acknowledged': raise ValueError('unexpected result kind')
    return row

def exact_listing(text, name):
    # Actual rustc 1.99 libtest output. A known optional trailing newline is the
    # only variation; zero/multiple tests and arbitrary extra output are refused.
    return text.rstrip('\n') == name + ': test\n\n1 test, 0 benchmarks'

def option_i32(value):
    return value=='None' or (value.startswith('Some(') and int(value[5:-1]) < 2**31)

def safe_failure(line):
    match=FAILURE.fullmatch(line)
    if not match or not option_i32(match[1]) or not option_i32(match[2]): return False
    if int(match[4]) > int(match[5]): return False
    summary=match[6]
    if summary=='none': return True
    entries=summary.split(',')
    if len(entries)>64: return False
    for entry in entries:
        parts=entry.split(':')
        if not parts or parts[0] not in BOUNDARIES: return False
        if len(parts)==2 and parts[1] in OUTCOMES: continue
        if len(parts)!=3 or not parts[1].startswith('IoKind=') or parts[1][7:] not in IO_KINDS or not parts[2].startswith('errno='): return False
        errno=parts[2][6:]
        if errno=='none': continue
        if not re.fullmatch(r'0|-?[1-9][0-9]{0,9}',errno) or not -(2**31)<=int(errno)<2**31: return False
    return True

def public_line(raw, name):
    if len(raw)>8192: return None
    line=raw.decode('utf8','strict').rstrip('\r')
    # No search inside arbitrary panic/text lines. Only libtest's exact prefix
    # or an entire standalone closed marker line is eligible for projection.
    prefix='test '+name+' ... '
    if line.startswith(prefix): line=line[len(prefix):]
    if CORE.fullmatch(line): return ('core',line)
    cleanup=CLEANUP.fullmatch(line)
    if cleanup and option_i32(cleanup[5]) and option_i32(cleanup[6]): return ('cleanup',line)
    if safe_failure(line): return ('failure',line)
    if line.startswith(MARKER): return ('outcome',public_outcome(line[len(MARKER):]))
    return None

class BoundedLines:
    """Oversized physical lines stay discarded until their actual newline."""
    def __init__(self):
        self.pending=bytearray()
        self.discarding=False

    def feed(self, chunk):
        lines=[]
        while chunk:
            split=chunk.find(b'\n')
            part=chunk if split<0 else chunk[:split]
            if not self.discarding:
                if len(self.pending)+len(part)>8192:
                    self.pending.clear()
                    self.discarding=True
                else:
                    self.pending.extend(part)
            if split<0: break
            if not self.discarding:
                lines.append(bytes(self.pending))
            self.pending.clear()
            self.discarding=False
            chunk=chunk[split+1:]
        return lines

def run_pure(executable):
    assert resource.getrlimit(resource.RLIMIT_CORE)[0] == 0
    for name in PURE_TESTS + POLICY_ENVELOPE_TESTS + PROMPT_RENDERING_TESTS:
        flags=['--exact',name,'--test-threads=1']
        listed=subprocess.run([executable,*flags,'--list'],capture_output=True,timeout=30,check=True)
        if not exact_listing(listed.stdout.decode(),name) or listed.stderr:
            raise ValueError('exact pure test not uniquely registered')
        # These 23 fixed source-reviewed cases use only modeled process state,
        # inert files, historical policy DTOs or fixed prompt rendering. They create
        # no native/IPC/network/payment owners.
        result=subprocess.run([executable,*flags],stdout=subprocess.PIPE,stderr=subprocess.STDOUT,timeout=30)
        if result.returncode!=0 or len(result.stdout)>1024*1024:
            print('CI_SYNTHETIC_PURE failed_test='+name,flush=True)
            raise RuntimeError('exact pure test failed; raw output withheld')
    print('CI_SYNTHETIC_PURE passed=23 raw_output_discarded=true',flush=True)

def run_storage_bootstrap(executable):
    assert resource.getrlimit(resource.RLIMIT_CORE)[0] == 0
    flags=['--exact',STORAGE_BOOTSTRAP_TEST,'--test-threads=1']
    listed=subprocess.run([executable,*flags,'--list'],capture_output=True,timeout=30,check=True)
    if not exact_listing(listed.stdout.decode(),STORAGE_BOOTSTRAP_TEST) or listed.stderr:
        raise ValueError('exact encrypted bootstrap test not uniquely registered')
    # Real maintained encrypted empty archive8 -> layered9 -> later pending
    # provenance regression. No terminal/IPC/native authority/payment owner.
    # Keep this result separate from the 18 pure/model/filesystem test cases.
    result=subprocess.run([executable,*flags],stdout=subprocess.PIPE,stderr=subprocess.STDOUT,timeout=300)
    if result.returncode!=0 or len(result.stdout)>1024*1024:
        print('CI_SYNTHETIC_ENCRYPTED_BOOTSTRAP passed=false raw_output_withheld=true',flush=True)
        raise RuntimeError('exact encrypted bootstrap regression failed')
    print('CI_SYNTHETIC_ENCRYPTED_BOOTSTRAP passed=true native_payment_verified=false',flush=True)

def run(executable, phase):
    assert resource.getrlimit(resource.RLIMIT_CORE)[0] == 0
    name, seconds = TESTS[phase]
    flags = ['--exact', name, '--test-threads=1'] + (['--ignored'] if phase=='full' else [])
    listed=subprocess.run([executable,*flags,'--list'],capture_output=True,timeout=30,check=True)
    assert exact_listing(listed.stdout.decode(),name) and not listed.stderr, 'Exact test not uniquely registered'
    started=time.monotonic(); process=subprocess.Popen([executable,*flags,'--nocapture'],stdout=subprocess.PIPE,stderr=subprocess.STDOUT)
    assert process.stdout is not None
    framing=BoundedLines(); total=0; cleanup=False; cleanups=0; cores=0; failures=0; outcome=None; status=None
    try:
        eof=False
        while not eof:
            if time.monotonic()-started > seconds: raise TimeoutError('outer runtime deadline')
            ready,_,_=select.select([process.stdout],[],[],0.2)
            if not ready: continue
            chunk=os.read(process.stdout.fileno(),65536)
            if not chunk: eof=True; continue
            total+=len(chunk)
            if total > 16*1024*1024: raise ValueError('bounded runtime output exceeded')
            for raw in framing.feed(chunk):
                try: projected=public_line(raw,name)
                except UnicodeError: projected=None
                if projected is None: continue
                kind,value=projected
                if kind=='core':
                    cores+=1
                    if cores>1: raise ValueError('duplicate core policy')
                    print(value,flush=True)
                elif kind=='cleanup':
                    cleanups+=1
                    if cleanups>1: raise ValueError('duplicate cleanup result')
                    fields=CLEANUP.fullmatch(value)
                    cleanup=fields[1]!='Unverified' and fields[2]=='OriginalGroupAbsentObserved' and fields[3]=='Reaped' and fields[4]=='ClosedAndAbsenceVerified' and fields[5]=='Some(0)' and fields[6]=='None' and fields[7]=='false'
                    print(value,flush=True)
                elif kind=='failure':
                    failures+=1
                    if failures>1: raise ValueError('duplicate failure result')
                    print(value,flush=True)
                elif kind=='outcome':
                    if phase!='full' or outcome is not None: raise ValueError('unexpected duplicate public outcome')
                    outcome=value
        status=process.wait(timeout=10)
    finally:
        if status is None:
            # This handles only our direct test parent. No claim about its
            # separate-session descendants; retain runtime root for job disposal.
            process.kill()
            try: process.wait(timeout=5)
            except subprocess.TimeoutExpired: pass
            print('CI_SYNTHETIC_RESULT cleanup_unverified=true outcome_unverified=true',flush=True)
    if status!=0 or not cleanup or cores!=1 or failures or (phase=='full' and outcome is None):
        raise RuntimeError('synthetic phase failed or required cleanup/outcome evidence missing')
    if outcome is not None:
        text=MARKER+json.dumps(outcome,separators=(',',':'),sort_keys=True)
        print(text,flush=True)
        summary=os.environ.get('GITHUB_STEP_SUMMARY')
        if summary:
            with open(summary,'a',encoding='utf8') as f:
                f.write('Synthetic-only payment receipt, not public-chain settlement:\n'+text+'\n')
    print(f'CI_SYNTHETIC_RESULT phase={phase} passed=true cleanup_verified=true',flush=True)

if __name__=='__main__':
    try:
        assert len(sys.argv)==3 and sys.argv[2] in {*TESTS,'pure','storage-bootstrap'}
        exe=pathlib.Path(sys.argv[1]).resolve(strict=True)
        assert exe.is_file() and exe.is_relative_to(pathlib.Path(os.environ['CARGO_TARGET_DIR']).resolve(strict=True))
        if sys.argv[2]=='pure': run_pure(str(exe))
        elif sys.argv[2]=='storage-bootstrap': run_storage_bootstrap(str(exe))
        else: run(str(exe),sys.argv[2])
    except Exception:
        # Never serialize arbitrary exception text or raw test output.
        print('CI_SYNTHETIC_RESULT passed=false details_withheld=true',flush=True)
        sys.exit(1)
