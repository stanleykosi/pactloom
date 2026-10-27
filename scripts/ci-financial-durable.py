#!/usr/bin/env python3
"""Closed NativeV3 durable correctness profile; import is inert.

This is not the coordinated/rendered-UI oracle. The explicit selective recipe
keeps only Signer and Engine at opt-level 0; it never changes an authority bound.
Runtime output remains private except for the exact finite receipts below.
"""
import ctypes
import hashlib
import json
import os
import pathlib
import re
import selectors
import signal
import subprocess
import time

PROFILE = 'financial-durable-result-lifecycle-selective-v2'
GATE = b'financial-durable-v2\n'
ROLE = 'durable-lifecycle-qualification'
ARTIFACTS = (ROLE,)
MANIFEST_VERSION = 3
FEATURE_TEXT = 'durable-proposal,synthetic-born-joined-qualification'
FEATURES = ['durable-proposal','financial-runtime','manual-admission','synthetic-born-joined-qualification']
OVERRIDES = ('profile.release.package.wholepact-signer.opt-level=0',
             'profile.release.package.wholepact-engine.opt-level=0')
PREFIX = ('host::manual_enrollment::command::roster_publication_v2::sequential_construction_v3::'
          'qualification::durable_proposal_v1::delivery_admission_v2::durable_result_lifecycle_v2::')
CASES = {
    'durable-resume': PREFIX + 'original_two_owner_durable_results_resume_unfinished_counterpart_v2',
    'durable-started': PREFIX + 'original_financial_started_without_result_remains_uncertain_after_process_death_v2',
}
SAFE_TESTS = ('host::manual_enrollment::command::roster_publication_v2::sequential_construction_v3::qualification::durable_proposal_v1::delivery_admission_v2::durable_result_lifecycle_v2::partial_ready_paths_reject_escape_alias_and_unpreserved_container', 'host::manual_enrollment::command::roster_publication_v2::sequential_construction_v3::qualification::durable_proposal_v1::delivery_admission_v2::durable_result_lifecycle_v2::partial_death_marker_cannot_promote_old_profile_or_partial_line', 'host::manual_enrollment::command::roster_publication_v2::sequential_construction_v3::qualification::durable_proposal_v1::delivery_admission_v2::durable_result_lifecycle_v2::intake_death_marker_requires_exact_committed_ack_boundary', 'host::manual_enrollment::command::roster_publication_v2::sequential_construction_v3::qualification::durable_proposal_v1::delivery_admission_v2::durable_result_lifecycle_v2::started_death_marker_cannot_claim_result_or_unterminated_line', 'host::financial::private_financial_v2::qualification_fault_v2::tests::intake_ack_fault_latch_is_one_shot_exact_and_rejects_elapsed_arm', 'host::financial::durable_financial_commands_v2::tests::exact_two_owner_command_keys_are_disjoint_and_profile_specific', 'host::financial::durable_financial_commands_v2::tests::versioned_command_selector_rejects_unknown_fields')
NATIVE_SECONDS = 1800
ATTACH_SECONDS = 1830
ATTACH_SUITE_SECONDS = 3660
RUNTIME_SUITE_SECONDS = 4080  # Two attach bounds plus original bounded Docker control/cleanup.
RUNTIME_AND_CLEANUP_SECONDS = 4800  # Includes separate destructive cleanup reserve; no native work.
MAX_OUTPUT = 1024 * 1024
MAX_LINE = 8192
A_FIELDS = ('producer_killed_reaped_group_absent','signer_result_preintake_checkpoint_verified',
    'intake_ack_child_killed_reaped_group_absent','observed_original_writer_expiry',
    'first_result_outbox_unchanged','first_exposure_unchanged','counterpart_unsigned_at_death',
    'fresh_second_owner_completed','exact_union_extraction_verified',
    'local_read_return_intake_finish_verified','reader_reaped_group_absent',
    'six_scoped_protocol_refusals_verified','economic_proposal_verifier_succeeded',
    'cleanup_verified','native_runtime_executed','live_funds')
B_FIELDS = ('producer_killed_reaped_group_absent','actual_native_reopen_source_kernel_uncertain',
    'started_one_result_zero_outbox_zero_unchanged','exposure_outstanding_uncertain',
    'reader_reaped_group_absent','cleanup_verified','native_runtime_executed','live_funds',
    'not_full_v2_result_opener_or_return_success')
NATIVE_PROFILES = {'durable-resume':'durable-result-lifecycle-v2',
                   'durable-started':'durable-result-started-uncertainty-v2'}
NATIVE_MARKERS = {'durable-resume':b'CI_SYNTHETIC_DURABLE_RESULT_V2 ',
                  'durable-started':b'CI_SYNTHETIC_DURABLE_STARTED_V2 '}
FAILURES = ('selector','start','timeout','output_limit','native_assertion','schema','cleanup','context','internal')

class Rejected(Exception):
    def __init__(self, code):
        self.code = code if code in FAILURES else 'internal'
        super().__init__(self.code)

def need(ok, code='schema'):
    if not ok: raise Rejected(code)

def pairs(items):
    value = {}
    for key, item in items:
        need(key not in value); value[key] = item
    return value

def loads(raw):
    need(type(raw) is bytes and 0 < len(raw) <= MAX_LINE)
    try:
        return json.loads(raw, object_pairs_hook=pairs,
            parse_constant=lambda _: (_ for _ in ()).throw(Rejected('schema')))
    except (ValueError, UnicodeError, RecursionError): raise Rejected('schema') from None

def recipe():
    return dict(build_recipe_version=4, qualification_profile=PROFILE,
        execution='native-owner-durable-correctness-selective-optimization',
        toolchain='1.99.0',rustc='rustc 1.99.0 (b940084d7 2026-09-28)',target='x86_64-unknown-linux-gnu',
        jobs=3,incremental=False,profile='release',default_features=False,
        host_test_features=FEATURE_TEXT,cargo_config_overrides=list(OVERRIDES),
        host_opt_level=3,signer_opt_level=0,engine_opt_level=0,
        debug_assertions=False,overflow_checks=False,other_dependencies_release_optimized=True,
        rustflags='',sqlcipher='4.19.0',openssl='3.5.9',static_crypto=True,platform='linux-amd64',locked=True,
        artifact_features={ROLE:list(FEATURES)},test_selectors=dict(CASES),safe_test_selectors=list(SAFE_TESTS),
        cfg_delivery=dict(mechanism='cargo-build-script-v1',mode_environment='WHOLEPACT_FINANCIAL_BUILD_MODE',
            build_scripts=['crates/wholepact-native-host/build.rs','crates/wholepact-signer/build.rs'],
            artifact_script_crates={ROLE:['wholepact-native-host','wholepact-signer']},
            artifact_modes={ROLE:'production'},effective_cfgs={ROLE:[]},global_financial_cfgs_permitted=False))

def validate_package_profiles(raw, repo):
    expected = {str(pathlib.Path(repo)/'crates'/name/'Cargo.toml'):name
                for name in ('wholepact-signer','wholepact-engine')}
    found = set()
    for line in raw.splitlines():
        need(len(line) <= 2*1024*1024)
        try: row = json.loads(line)
        except (ValueError,UnicodeError): continue
        if type(row) is not dict or row.get('reason') != 'compiler-artifact': continue
        name = expected.get(row.get('manifest_path'))
        if name is None: continue
        target, profile = row.get('target'), row.get('profile')
        if type(target) is not dict or target.get('kind') != ['lib']: continue
        need(target.get('name') == name.replace('-','_') and type(profile) is dict
             and profile.get('opt_level') == '0' and profile.get('debug_assertions') is False
             and profile.get('test') is False)
        need(profile.get('overflow_checks') is False)
        need(name not in found); found.add(name)
    need(found == {'wholepact-signer','wholepact-engine'})

def safe_test_passed(selector, raw):
    """Producer-only exact safe test; never accepts the ignored lifecycle cases."""
    need(selector in SAFE_TESTS and type(raw) is bytes and len(raw)<=MAX_OUTPUT,'selector')
    named=summary=0
    for line in raw.splitlines():
        need(len(line)<=MAX_LINE,'output_limit')
        if line.startswith(b'test ') and not line.startswith(b'test result:'):
            need(line == b'test '+selector.encode()+b' ... ok','selector');named+=1
        if line.startswith(b'test result:'):
            need(re.fullmatch(rb'test result: ok\. 1 passed; 0 failed; 0 ignored; 0 measured; [0-9]{1,6} filtered out; finished in [0-9]{1,4}\.[0-9]{2}s',line) is not None,'native_assertion')
            summary+=1
    need(named==summary==1,'selector')

def native_receipt(case, raw):
    need(case in CASES, 'selector')
    value = loads(raw)
    fields = A_FIELDS if case == 'durable-resume' else B_FIELDS
    need(type(value) is dict and set(value) == {'profile',*fields}
         and value['profile'] == NATIVE_PROFILES[case])
    need(all(type(value[name]) is bool for name in fields))
    return value

def native_passed(case, value):
    fields = A_FIELDS if case == 'durable-resume' else B_FIELDS
    return all(value[name] is (name != 'live_funds') for name in fields)

class TestOutput:
    """Only one exact native receipt plus the actual one-test harness result."""
    def __init__(self, case):
        need(case in CASES,'selector')
        self.case,self.receipt,self.named,self.summary = case,None,0,0
    def line(self, line):
        need(type(line) is bytes and len(line) <= MAX_LINE,'output_limit')
        line = line.rstrip(b'\r')
        prefix=b'test '+CASES[self.case].encode()+b' ... '
        if line.startswith(prefix):
            self.named+=1;line=line[len(prefix):]
        elif line.startswith(b'test ') and not line.startswith(b'test result:'):
            raise Rejected('selector')
        for case, marker in NATIVE_MARKERS.items():
            if line.startswith(marker):
                need(case == self.case and self.receipt is None)
                self.receipt = native_receipt(case,line[len(marker):])
        if line.startswith(b'test result:'):
            need(re.fullmatch(rb'test result: ok\. 1 passed; 0 failed; 0 ignored; 0 measured; [0-9]{1,6} filtered out; finished in [0-9]{1,4}\.[0-9]{2}s',line) is not None,'native_assertion')
            self.summary += 1
    def finish(self, status):
        need(type(status) is int and status == 0,'native_assertion')
        need(self.named == self.summary == 1 and self.receipt is not None,'selector')
        need(native_passed(self.case,self.receipt),'native_assertion')
        return self.receipt

def candidate(case, source, receipt):
    return dict(schema=1,profile=PROFILE,source=source,case=case,native_receipt=receipt,
                test_exit=0,owned_test_reaped=True,namespace_processes_absent=True,fixture_directory_absent=True)

def validate_candidate(value, case, source):
    need(type(value) is dict and set(value)=={'schema','profile','source','case','native_receipt',
         'test_exit','owned_test_reaped','namespace_processes_absent','fixture_directory_absent'})
    need(type(value['schema']) is int and value['schema']==1 and value['profile']==PROFILE
         and value['source']==source and value['case']==case)
    receipt=native_receipt(case,json.dumps(value['native_receipt'],separators=(',',':')).encode())
    need(native_passed(case,receipt) and type(value['test_exit']) is int and value['test_exit']==0)
    need(all(value[k] is True for k in ('owned_test_reaped','namespace_processes_absent','fixture_directory_absent')))
    return value

class RuntimeRecords:
    def __init__(self,case,source): self.case,self.source,self.result,self.failure=case,source,None,None
    def __call__(self,line):
        marker=b'CI_FINANCIAL_DURABLE_CANDIDATE '
        if line.startswith(marker):
            need(self.result is None and self.failure is None)
            self.result=validate_candidate(loads(line[len(marker):]),self.case,self.source)
        elif line.startswith(b'CI_FINANCIAL_DURABLE_FAILURE '):
            need(self.failure is None and self.result is None)
            value=loads(line[len(b'CI_FINANCIAL_DURABLE_FAILURE '):])
            need(type(value) is dict and set(value)=={'schema','profile','case','code','native_receipt','cleanup_unverified'}
                 and type(value['schema']) is int and value['schema']==1 and value['profile']==PROFILE
                 and value['case']==self.case and value['code'] in FAILURES
                 and type(value['cleanup_unverified']) is bool)
            if value['native_receipt'] is not None:
                native_receipt(self.case,json.dumps(value['native_receipt'],separators=(',',':')).encode())
            self.failure=value
        else: need(False)
    def finish(self,status):
        need(type(status) is int and status==0 and self.failure is None and self.result is not None,'native_assertion')
        return self.result

def run_case(case, manifest, original_deadline_ns):
    """PID1-only after verified root setup and permanent identity/cap drop."""
    process=None; root=None; first=None; receipt=None; output=None; cleanup_unverified=True
    try:
        need(case in CASES,'selector')
        need(os.getpid()==1 and os.getresuid()==(10001,)*3 and os.getresgid()==(10001,)*3
             and not os.getgroups() and manifest['profile']==PROFILE,'context')
        root=pathlib.Path('/ci-fixture')/({'durable-resume':'a','durable-started':'b'}[case]);root.mkdir(mode=0o700)
        deadline=original_deadline_ns/1e9
        need(time.monotonic()<deadline,'timeout')
        executable=pathlib.Path('/opt/ci-financial')/ROLE
        output=TestOutput(case)
        try:
            process=subprocess.Popen([str(executable),'--exact',CASES[case],'--ignored','--nocapture',
                '--test-threads=1','--color=never'],stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,close_fds=True,start_new_session=True,
                env={'PATH':'/usr/bin:/bin','TMPDIR':str(root),'LANG':'C.UTF-8','RUST_BACKTRACE':'0'})
        except OSError: raise Rejected('start') from None
        need(os.getpgid(process.pid)==process.pid,'start')
        total=0;pending=bytearray()
        with selectors.DefaultSelector() as selector:
            selector.register(process.stdout,selectors.EVENT_READ)
            while True:
                left=deadline-time.monotonic();need(left>0,'timeout')
                events=selector.select(left);need(events,'timeout')
                chunk=os.read(process.stdout.fileno(),32768)
                if not chunk:break
                total+=len(chunk);need(total<=MAX_OUTPUT,'output_limit');pending.extend(chunk)
                while b'\n' in pending:
                    line,_,tail=pending.partition(b'\n');pending=bytearray(tail);output.line(bytes(line))
                need(len(pending)<=MAX_LINE,'output_limit')
        need(not pending)
        receipt=output.finish(process.wait(timeout=max(.001,deadline-time.monotonic())))
        process.stdout.close()
        need(not list(root.iterdir()),'cleanup');root.rmdir()
        need({int(p.name) for p in pathlib.Path('/proc').iterdir() if p.name.isdecimal()}=={1},'cleanup')
        cleanup_unverified=False
        print('CI_FINANCIAL_DURABLE_CANDIDATE '+json.dumps(candidate(case,manifest['source_commit'],receipt),sort_keys=True,separators=(',',':')),flush=True)
        return 0
    except BaseException as error:
        receipt=output.receipt if output is not None else None
        first=error.code if isinstance(error,Rejected) else ('timeout' if isinstance(error,subprocess.TimeoutExpired) else 'internal')
    finally:
        if first is not None and process is not None:
            # Before wait/reap, this parent still owns the leader identity. On
            # any uncertainty the outer container owner destroys the namespace.
            try:
                if process.returncode is None: os.killpg(process.pid,signal.SIGKILL)
            except ProcessLookupError: pass
            except BaseException: cleanup_unverified=True  # Never overwrite the initiating failure.
            try: process.wait(timeout=5)
            except BaseException: cleanup_unverified=True  # Never overwrite the initiating failure.
            try: process.stdout.close()
            except BaseException: cleanup_unverified=True  # Never overwrite the initiating failure.
    print('CI_FINANCIAL_DURABLE_FAILURE '+json.dumps(dict(schema=1,profile=PROFILE,case=case if case in CASES else 'invalid',code=first or 'internal',native_receipt=receipt,cleanup_unverified=cleanup_unverified),sort_keys=True,separators=(',',':')),flush=True)
    return 1
