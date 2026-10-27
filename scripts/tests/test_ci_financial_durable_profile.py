#!/usr/bin/env python3
"""Pure closed-profile/parser tests. Fabricated ELF/receipt data is never executed.

These are codec and source-recipe assertions, not native authority, process-death,
cleanup, or financial-success evidence. Legacy oracle hashes predate this profile.
"""
import copy
import ast
import io
import contextlib
import hashlib
import importlib.util
import json
import pathlib
import re
import tempfile
import unittest
from unittest.mock import patch, Mock

ROOT = pathlib.Path(__file__).resolve().parents[1]
def load(name):
    spec = importlib.util.spec_from_file_location('durable_test_' + name.replace('-', '_'), ROOT / (name + '.py'))
    module = importlib.util.module_from_spec(spec); spec.loader.exec_module(module)
    return module
D = load('ci-financial-durable')
A = load('ci-financial-artifacts')
I = load('ci-financial-image')
S = load('ci-financial-supervisor')
PROFILE = 'financial-durable-result-lifecycle-selective-v2'
ROLE = 'durable-lifecycle-qualification'
SOURCE = 'a' * 40
IDENTITY = dict(repository='stanleykosi/pactloom', source=SOURCE, source_tree='b'*40, run_id=123, attempt=1)
CLOSURE = {path:'c'*64 for path in A.BUILD_SCRIPTS}
PREFIX = ('host::manual_enrollment::command::roster_publication_v2::sequential_construction_v3::'
          'qualification::durable_proposal_v1::delivery_admission_v2::durable_result_lifecycle_v2::')
CASES = {'durable-resume': PREFIX + 'original_two_owner_durable_results_resume_unfinished_counterpart_v2',
         'durable-started': PREFIX + 'original_financial_started_without_result_remains_uncertain_after_process_death_v2'}
SAFE = tuple(PREFIX + tail for tail in (
    'partial_ready_paths_reject_escape_alias_and_unpreserved_container',
    'partial_death_marker_cannot_promote_old_profile_or_partial_line',
    'intake_death_marker_requires_exact_committed_ack_boundary',
    'started_death_marker_cannot_claim_result_or_unterminated_line')) + (
    'host::financial::private_financial_v2::qualification_fault_v2::tests::intake_ack_fault_latch_is_one_shot_exact_and_rejects_elapsed_arm',
    'host::financial::durable_financial_commands_v2::tests::exact_two_owner_command_keys_are_disjoint_and_profile_specific',
    'host::financial::durable_financial_commands_v2::tests::versioned_command_selector_rejects_unknown_fields')
NEW_LEAF_SAFE = tuple(PREFIX + tail for tail in (
    'durable_failure_v2_preserves_setup_and_tls_errors_without_private_text',
    'durable_failure_v2_projects_each_returned_stage_rejection_and_healthy_status',
    'durable_failure_v2_preserves_first_failure_through_all_cleanup_modes',
    'durable_failure_v2_covers_all_final_boundaries_and_diagnostic_states'))
NEW_COLLECTOR_SAFE = tuple('host::manual_enrollment::command::roster_publication_v2::sequential_construction_v3::qualification::rolling_transcript_v1::delivery_first_failure_tests::' + tail for tail in (
    'delivery_first_failure_survives_more_than_64_later_diagnostics',
    'delivery_first_failure_requires_complete_exact_finite_marker',
    'delivery_first_failure_is_opt_in_and_isolated_per_child',
    'delivery_first_failure_insufficient_capture_budget_is_sticky'))
LEGACY_SAFE = SAFE
SAFE = SAFE + NEW_LEAF_SAFE + NEW_COLLECTOR_SAFE
SUMMARY = b'test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 17 filtered out; finished in 0.01s'
LEGACY_GOLDEN = {
    'coordinated-financial-external-pre-v3-witness-v1': '31bdd6c62252ef49e14b301be720406f17b5099bf0966a37ce20afb86dc71ac7',
    'coordinated-financial-rendered-host-semantic-v1': '5ba312cac7a7b31c440ef1582dc8f453a194345aedab734d163344325ebd34ca',
}

def raw(value): return json.dumps(value, sort_keys=True, separators=(',', ':')).encode()
def inert_receipt(case):
    fields = D.A_FIELDS if case == 'durable-resume' else D.B_FIELDS
    return dict(profile=D.NATIVE_PROFILES[case], **{name:name != 'live_funds' for name in fields})
def native_lines(case, coalesced=False):
    named = b'test ' + CASES[case].encode() + b' ... '
    marker = D.NATIVE_MARKERS[case] + raw(inert_receipt(case))
    return [named + marker, b'ok', SUMMARY] if coalesced else [named + b'ok', marker, SUMMARY]
def parse_native(case, lines, status=0):
    output = D.TestOutput(case)
    for line in lines: output.line(line)
    return output.finish(status)

class DurableRecipeTests(unittest.TestCase):
    def test_safe_selectors_have_exact_owning_source_declarations(self):
        leaves = [(SAFE[:4], 'crates/wholepact-native-host/src/host/manual_enrollment/command/roster_publication_v2/sequential_construction_v3_qualification/durable_proposal_v1/durable_result_lifecycle_v2.rs'),
                  (SAFE[4:5], 'crates/wholepact-native-host/src/host/financial/private_financial_v2/qualification_fault_v2.rs'),
                  (SAFE[5:7], 'crates/wholepact-native-host/src/host/financial/durable_financial_commands_v2.rs'),
                  (NEW_LEAF_SAFE, 'crates/wholepact-native-host/src/host/manual_enrollment/command/roster_publication_v2/sequential_construction_v3_qualification/durable_proposal_v1/durable_result_lifecycle_v2.rs'),
                  (NEW_COLLECTOR_SAFE, 'crates/wholepact-native-host/src/host/manual_enrollment/command/roster_publication_v2/sequential_construction_v3_qualification/rolling_transcript_v1.rs')]
        for selectors,path in leaves:
            text=(ROOT.parent/path).read_text()
            for selector in selectors:
                name=selector.rsplit('::',1)[1]
                self.assertEqual(len(re.findall(r'#\[test\]\s*fn '+re.escape(name)+r'\(',text)),1,selector)
                if selector in NEW_COLLECTOR_SAFE:
                    self.assertIn('::rolling_transcript_v1::delivery_first_failure_tests::',selector)
                    self.assertGreater(text.index('fn '+name+'('),text.index('mod delivery_first_failure_tests {'))

    def test_closed_recipe_and_selector_inventory(self):
        self.assertEqual(D.PROFILE, PROFILE); self.assertEqual(D.ROLE, ROLE)
        self.assertEqual(D.CASES, CASES); self.assertEqual(D.SAFE_TESTS, SAFE)
        self.assertEqual(D.SAFE_TESTS[:7],LEGACY_SAFE);self.assertEqual(len(D.SAFE_TESTS),15)
        self.assertEqual(len(SAFE), len(set(SAFE))); self.assertFalse(set(SAFE) & set(CASES.values()))
        self.assertEqual(D.recipe(), dict(build_recipe_version=4, qualification_profile=PROFILE,
            execution='native-owner-durable-correctness-selective-optimization', toolchain='1.99.0',
            rustc='rustc 1.99.0 (b940084d7 2026-09-28)',target='x86_64-unknown-linux-gnu',jobs=3,
            incremental=False,profile='release',default_features=False,
            host_test_features='durable-proposal,synthetic-born-joined-qualification',
            cargo_config_overrides=['profile.release.package.wholepact-signer.opt-level=0',
                                    'profile.release.package.wholepact-engine.opt-level=0'],
            host_opt_level=3,signer_opt_level=0,engine_opt_level=0,debug_assertions=False,
            overflow_checks=False,other_dependencies_release_optimized=True,rustflags='',
            sqlcipher='4.19.0',openssl='3.5.9',static_crypto=True,platform='linux-amd64',locked=True,
            artifact_features={ROLE:['durable-proposal','financial-runtime','manual-admission','synthetic-born-joined-qualification']},
            test_selectors=CASES,safe_test_selectors=list(SAFE),cfg_delivery=dict(mechanism='cargo-build-script-v1',
                mode_environment='WHOLEPACT_FINANCIAL_BUILD_MODE',
                build_scripts=['crates/wholepact-native-host/build.rs','crates/wholepact-signer/build.rs'],
                artifact_script_crates={ROLE:['wholepact-native-host','wholepact-signer']},
                artifact_modes={ROLE:'production'},effective_cfgs={ROLE:[]},global_financial_cfgs_permitted=False)))
        self.assertEqual((D.NATIVE_SECONDS,D.ATTACH_SECONDS,D.ATTACH_SUITE_SECONDS), (1800,1830,3660))
        self.assertEqual((D.RUNTIME_SUITE_SECONDS,D.RUNTIME_AND_CLEANUP_SECONDS), (4080,4800))

    def test_actual_package_profile_records_require_both_exact_libraries(self):
        repo = '/inert-source'
        def row(name):
            return dict(reason='compiler-artifact',manifest_path=f'{repo}/crates/{name}/Cargo.toml',
                target={'name':name.replace('-','_'),'kind':['lib']},
                profile=dict(opt_level='0',debug_assertions=False,overflow_checks=False,test=False))
        records = [row('wholepact-signer'), row('wholepact-engine')]
        encode = lambda values:b'\n'.join(raw(v) for v in values)
        D.validate_package_profiles(encode(records), repo)
        for values in (records[:1], records[1:], records + records[:1]):
            with self.assertRaises(D.Rejected): D.validate_package_profiles(encode(values), repo)
        for index in range(2):
            for field,bad in [('opt_level','3'),('debug_assertions',True),('overflow_checks',True),
                              ('test',True),('debug_assertions',0),('overflow_checks',0),('test',0)]:
                changed=copy.deepcopy(records); changed[index]['profile'][field]=bad
                with self.subTest(index=index,field=field,bad=bad), self.assertRaises(D.Rejected):
                    D.validate_package_profiles(encode(changed), repo)
            for field in records[index]['profile']:
                changed=copy.deepcopy(records); del changed[index]['profile'][field]
                with self.assertRaises(D.Rejected): D.validate_package_profiles(encode(changed), repo)
            for slot,key,bad in [('target','name','wrong'),('target','kind',['bin'])]:
                changed=copy.deepcopy(records); changed[index][slot][key]=bad
                with self.assertRaises(D.Rejected): D.validate_package_profiles(encode(changed), repo)
            changed=copy.deepcopy(records); changed[index]['manifest_path']='/wrong/Cargo.toml'
            with self.assertRaises(D.Rejected): D.validate_package_profiles(encode(changed), repo)

    def test_safe_selectors_cannot_accept_ignored_lifecycle_or_zero_tests(self):
        for selector in SAFE:
            good=b'test '+selector.encode()+b' ... ok\n'+SUMMARY+b'\n'
            D.safe_test_passed(selector,good)
            for bad in (good+good, good.replace(b' ... ok',b' ... FAILED'),
                        good.replace(b'1 passed',b'0 passed'),good.replace(b'0 ignored',b'1 ignored'),
                        SUMMARY+b'\n',good.replace(selector.encode(),b'wrong')):
                with self.assertRaises(D.Rejected): D.safe_test_passed(selector,bad)
        for selector in (*CASES.values(),'unknown'):
            with self.assertRaises(D.Rejected): D.safe_test_passed(selector,b'')

class DurableReceiptTests(unittest.TestCase):
    def test_native_receipts_are_case_specific_strict_json_and_boolean(self):
        for case in CASES:
            value=inert_receipt(case); self.assertEqual(D.native_receipt(case,raw(value)),value)
            self.assertTrue(D.native_passed(case,value))
            for key in set(value)-{'profile'}:
                for bad in (0,1,None,'true'):
                    changed={**value,key:bad}
                    with self.subTest(case=case,key=key,bad=bad), self.assertRaises(D.Rejected):
                        D.native_receipt(case,raw(changed))
                changed={**value,key:not value[key]}
                self.assertFalse(D.native_passed(case,D.native_receipt(case,raw(changed))))
            for changed in ({**value,'extra':True},{k:v for k,v in value.items() if k!='profile'},
                            {**value,'profile':PROFILE}):
                with self.assertRaises(D.Rejected): D.native_receipt(case,raw(changed))
            encoded=raw(value)
            for malformed in (encoded.replace(b'{',b'{"profile":"duplicate",',1), b'NaN',b'null',b'[]',b'\xff',
                              encoded+b'{}',b' '* (D.MAX_LINE+1)):
                with self.assertRaises(D.Rejected): D.native_receipt(case,malformed)
            other=next(x for x in CASES if x!=case)
            with self.assertRaises(D.Rejected): D.native_receipt(case,raw(inert_receipt(other)))
        with self.assertRaises(D.Rejected): D.native_receipt('unknown',b'{}')

    def test_real_libtest_separate_and_coalesced_prefix_shapes(self):
        for case in CASES:
            for coalesced in (False,True):
                lines=native_lines(case,coalesced)
                self.assertEqual(parse_native(case,lines),inert_receipt(case))
                self.assertEqual(parse_native(case,[line+b'\r' for line in lines]),inert_receipt(case))
            lines=native_lines(case)
            for bad in (lines[1:],lines[:1]+lines[2:],lines[:-1],lines+[lines[1]],lines+[lines[0]],
                        lines+[SUMMARY],[lines[0].replace(CASES[case].encode(),b'wrong'),*lines[1:]],
                        [*lines[:-1],SUMMARY.replace(b'1 passed',b'0 passed')],
                        [*lines[:-1],SUMMARY.replace(b'0 ignored',b'1 ignored')]):
                with self.assertRaises(D.Rejected): parse_native(case,bad)
            other=next(x for x in CASES if x!=case)
            with self.assertRaises(D.Rejected): parse_native(case,native_lines(other))
            for status in (1,-9,False,True,None):
                with self.assertRaises(D.Rejected): parse_native(case,lines,status)
            failed=inert_receipt(case); failed['live_funds']=True
            with self.assertRaises(D.Rejected): parse_native(case,[lines[0],D.NATIVE_MARKERS[case]+raw(failed),SUMMARY])
            with self.assertRaises(D.Rejected): D.TestOutput(case).line(b'x'*(D.MAX_LINE+1))
        with self.assertRaises(D.Rejected): D.TestOutput('unknown')

    def test_candidate_requires_exact_source_case_and_all_cleanup_fields(self):
        for case in CASES:
            value=D.candidate(case,SOURCE,inert_receipt(case))
            self.assertEqual(D.validate_candidate(value,case,SOURCE),value)
            mutations=[{**value,'extra':True},{k:v for k,v in value.items() if k!='native_receipt'}]
            for key,bad in [('schema',True),('schema',2),('profile','legacy'),('source','b'*40),
                            ('case','unknown'),('test_exit',False),('test_exit',1)]:
                mutations.append({**value,key:bad})
            for key in ('owned_test_reaped','namespace_processes_absent','fixture_directory_absent'):
                for bad in (False,1,None):mutations.append({**value,key:bad})
            for changed in mutations:
                with self.assertRaises(D.Rejected): D.validate_candidate(changed,case,SOURCE)
            for key in set(value['native_receipt'])-{'profile'}:
                changed=copy.deepcopy(value);changed['native_receipt'][key]=not changed['native_receipt'][key]
                with self.assertRaises(D.Rejected):D.validate_candidate(changed,case,SOURCE)

    def test_runtime_records_are_single_success_or_failure_never_both(self):
        for case in CASES:
            candidate=b'CI_FINANCIAL_DURABLE_CANDIDATE '+raw(D.candidate(case,SOURCE,inert_receipt(case)))
            failure=b'CI_FINANCIAL_DURABLE_FAILURE '+raw(dict(schema=1,profile=PROFILE,case=case,code='cleanup',native_receipt=None,cleanup_unverified=True))
            records=D.RuntimeRecords(case,SOURCE);records(candidate)
            self.assertEqual(records.finish(0)['case'],case)
            for lines in ([candidate,candidate],[failure,failure],[failure,candidate],[candidate,failure],
                          [b'unknown'],[candidate.replace(b'"schema":1',b'"schema":1,"schema":1')]):
                records=D.RuntimeRecords(case,SOURCE)
                with self.assertRaises(D.Rejected):
                    for line in lines:records(line)
            for lines in ([],[failure]):
                records=D.RuntimeRecords(case,SOURCE)
                for line in lines:records(line)
                with self.assertRaises(D.Rejected):records.finish(0)
            for status in (1,-9,False):
                records=D.RuntimeRecords(case,SOURCE);records(candidate)
                with self.assertRaises(D.Rejected):records.finish(status)

    def test_failure_can_retain_partial_native_facts_but_never_pass(self):
        for case in CASES:
            full=inert_receipt(case);partial={**full,'cleanup_verified':False}
            base=dict(schema=1,profile=PROFILE,case=case,code='native_assertion',
                      native_receipt=None,cleanup_unverified=True)
            for native in (None,partial,full):
                for cleanup in (False,True):
                    value={**base,'native_receipt':native,'cleanup_unverified':cleanup}
                    records=D.RuntimeRecords(case,SOURCE)
                    records(b'CI_FINANCIAL_DURABLE_FAILURE '+raw(value))
                    self.assertEqual(records.failure,value)
                    for status in (0,1):
                        with self.assertRaises(D.Rejected):records.finish(status)
            other=next(x for x in CASES if x!=case)
            bad_receipts=(inert_receipt(other),{**full,'cleanup_verified':1},{**full,'extra':True},[],False)
            mutants=[{**base,'native_receipt':value} for value in bad_receipts]
            mutants += [{**base,key:bad} for key,bad in [('schema',True),('schema',2),('profile','legacy'),
                ('case',other),('code','private arbitrary error text'),('cleanup_unverified',1),('cleanup_unverified',None)]]
            mutants += [{k:v for k,v in base.items() if k!=key} for key in base]
            mutants.append({**base,'extra':0})
            for value in mutants:
                records=D.RuntimeRecords(case,SOURCE)
                with self.assertRaises(D.Rejected):records(b'CI_FINANCIAL_DURABLE_FAILURE '+raw(value))

class DurableBundleTests(unittest.TestCase):
    def make_bundle(self,profile):
        temp=tempfile.TemporaryDirectory();self.addCleanup(temp.cleanup);root=pathlib.Path(temp.name)
        inputs=root/'inputs';inputs.mkdir()
        for name in A.bundle_names(profile):
            (inputs/name).write_bytes(b'\x7fELFfabricated, never executable '+name.encode())
        output=root/'bundle.tar';value=A.export_bundle(inputs,output,IDENTITY,CLOSURE,profile)
        return output,value

    def test_version_three_single_role_roundtrip_is_not_a_legacy_bundle(self):
        output,value=self.make_bundle(PROFILE)
        self.assertEqual(A.verify_bundle(output,IDENTITY,CLOSURE,PROFILE),value)
        self.assertEqual(value['version'],3);self.assertEqual(set(value['files']),{ROLE})
        self.assertEqual(value['recipe'],D.recipe())
        for profile in LEGACY_GOLDEN:
            with self.assertRaises(A.Rejected): A.verify_bundle(output,IDENTITY,CLOSURE,profile)
        for profile in ('unknown','financial-durable-result-lifecycle-v2',''):
            for method in (A.bundle_names,A.manifest_version,A.recipe):
                with self.assertRaises(A.Rejected): method(profile)

    def test_exact_recipe_manifest_role_and_provenance_mutations_reject(self):
        _,value=self.make_bundle(PROFILE)
        mutations=[{**value,'extra':0},{**value,'version':2},{**value,'version':True}]
        for key in value:
            changed=copy.deepcopy(value);del changed[key];mutations.append(changed)
        for key,bad in [('host_opt_level',0),('signer_opt_level',3),('engine_opt_level',3),
                        ('debug_assertions',True),('overflow_checks',True),('jobs',4),('locked',1),
                        ('default_features',0),('static_crypto',1),('rustflags','--cfg forged'),
                        ('cargo_config_overrides',[]),('test_selectors',{}),('safe_test_selectors',[]),
                        ('build_recipe_version',3),('qualification_profile',A.SEMANTIC_PROFILE)]:
            changed=copy.deepcopy(value);changed['recipe'][key]=bad;mutations.append(changed)
        for bad_files in ({},{**value['files'],'pristine-setup':value['files'][ROLE]},
                          {'pristine-setup':value['files'][ROLE]}):
            mutations.append({**value,'files':bad_files})
        for changed in mutations:
            with self.assertRaises(A.Rejected): A.validate_manifest(changed,IDENTITY,CLOSURE,PROFILE)
        for identity in ({**IDENTITY,'source':'f'*40},{**IDENTITY,'attempt':True},{**IDENTITY,'run_id':124}):
            with self.assertRaises(A.Rejected): A.validate_manifest(value,identity,CLOSURE,PROFILE)
        with self.assertRaises(A.Rejected): A.validate_manifest(value,IDENTITY,{**CLOSURE,'Cargo.lock':'d'*64},PROFILE)

    def test_legacy_archives_remain_byte_exact_against_prechange_oracles(self):
        for profile,expected in LEGACY_GOLDEN.items():
            output,value=self.make_bundle(profile)
            self.assertEqual(hashlib.sha256(output.read_bytes()).hexdigest(),expected)
            self.assertEqual(value['version'],2);self.assertEqual(set(value['files']),set(A.NAMES))
            self.assertEqual(A.verify_bundle(output,IDENTITY,CLOSURE,profile),value)
            with self.assertRaises(A.Rejected): A.verify_bundle(output,IDENTITY,CLOSURE,PROFILE)

    def test_legacy_image_text_remains_byte_exact_under_explicit_profile(self):
        for profile in LEGACY_GOLDEN:
            with patch.object(I,'profile',return_value=profile):
                self.assertEqual(hashlib.sha256(I.installer().encode()).hexdigest(),
                    '09414396d408db84041b40e6697687178def85d847922655b38bc29070eb6cc5')
                self.assertEqual(hashlib.sha256(I.dockerfile().encode()).hexdigest(),
                    '992aea1b5c801a1a64c83f6ddb4cfff6c9fc0cd06b407eeb5919074b3c156d93')

class DurableSelectionTests(unittest.TestCase):
    def test_mocked_v2_containment_and_removal_precede_pass(self):
        # Every external command/control boundary is replaced. No Docker,
        # process, socket, credential, fixture or privilege change is executed.
        case='durable-resume';token='owned';image='sha256:'+'d'*64
        name='wp-financial-'+token+'-'+case
        expected=['create','--pull','never','--name',name,'--label',S.LABEL+'='+token,
            '--label',S.SOURCE_LABEL+'='+SOURCE,'--network','none','--read-only','--cap-drop','ALL',
            '--cap-add','SETUID','--cap-add','SETGID','--security-opt','no-new-privileges:true',
            '--pids-limit','128','--memory','2g','--memory-swap','2g','--cpus','4',
            '--ipc','private','--cgroupns','private','--ulimit','core=0:0','--ulimit','nofile=512:512',
            '--log-driver','none','--restart','no']
        mounts={
            '/etc/wholepact':'rw,noexec,nosuid,nodev,size=64k,mode=0755',
            '/run/ci-account':'rw,noexec,nosuid,nodev,size=64k,mode=0755',
            '/ci-fixture':'rw,noexec,nosuid,nodev,size=512m,uid=10001,gid=10001,mode=0700',
            '/run/ci-financial-wayland':'rw,noexec,nosuid,nodev,size=16m,uid=10001,gid=10001,mode=0700',
            '/ci-financial-evidence':'rw,noexec,nosuid,nodev,size=64m,uid=10001,gid=10001,mode=0700',
            '/ci-financial-control':'rw,noexec,nosuid,nodev,size=1m,uid=10001,gid=10001,mode=0700',
            '/tmp':'rw,noexec,nosuid,nodev,size=64m,mode=1777',
            '/dev/shm':'rw,noexec,nosuid,nodev,size=128m,mode=1777'}
        self.assertEqual(S.TMPFS,mounts)
        for path,options in mounts.items():expected+=['--tmpfs',path+':'+options]
        expected += [image,case]
        for fault in (None,'remove','exit','namespace'):
            with self.subTest(fault=fault),contextlib.ExitStack() as stack:
                events=[]
                def create(args,*unused,**kwargs):
                    self.assertEqual(args,expected);events.append('create');return b''
                def attach(args,*unused,**kwargs):
                    self.assertEqual(args,['docker','start','--attach',name]);events.append('attach')
                    value=D.candidate(case,SOURCE,inert_receipt(case))
                    if fault=='namespace':value['namespace_processes_absent']=False
                    kwargs['on_line'](b'CI_FINANCIAL_DURABLE_CANDIDATE '+raw(value))
                    return (1 if fault=='exit' else 0),b''
                def remove(*args):
                    self.assertEqual(args,(name,token));events.append('remove')
                    if fault=='remove':raise S.Failure('cleanup','container_remaining')
                stack.enter_context(patch.object(S,'names',return_value=[]))
                stack.enter_context(patch.object(S,'docker',side_effect=create))
                stack.enter_context(patch.object(S,'inspect_isolation',side_effect=lambda *args:events.append('inspect')))
                stack.enter_context(patch.object(S,'command',side_effect=attach))
                stack.enter_context(patch.object(S,'docker_env',return_value={'PATH':'/usr/bin:/bin'}))
                stack.enter_context(patch.object(S,'remove_container',side_effect=remove))
                stack.enter_context(patch.object(S,'emit'))
                stack.enter_context(patch.object(S,'_DURABLE_DOCKER_DEADLINE',1000))
                stack.enter_context(patch.object(S.time,'monotonic',return_value=10))
                result,passed=S.run_case(case,image,token,SOURCE)
                self.assertIs(passed,fault is None)
                self.assertEqual(events,['create','inspect','attach','remove'])

    def test_actual_default_v2_image_routing_is_not_legacy_context(self):
        self.assertEqual((ROOT/'qualification-gate-mode').read_bytes(),b'financial-durable-v2\n')
        self.assertEqual(I.profile(),PROFILE);self.assertEqual(I.artifact_files(),(ROLE,))
        runtime=I.runtime_files()
        self.assertEqual(len(runtime),12);self.assertEqual(len(set(runtime)),12)
        self.assertEqual(runtime.count('ci-financial-durable.py'),1)
        installer=I.installer();compile(installer,'inert-generated-v2-installer','exec')
        self.assertIn('ARTIFACT_FILES = '+repr((ROLE,)),installer)
        self.assertIn("10001 if name == 'durable-lifecycle-qualification' else 0",installer)
        dockerfile=I.dockerfile()
        self.assertIn('COPY --chown=10001:10001 --chmod=0555 artifacts/'+ROLE,dockerfile)
        for old in A.NAMES:self.assertNotIn('artifacts/'+old,dockerfile)
        self.assertIn('inputs/ci-financial-durable.py',dockerfile)
        self.assertNotIn('apt-get',dockerfile);self.assertIn('RUN --network=none',dockerfile)

    def test_host_recipe_and_actual_artifact_report_are_exact(self):
        expected=['rustup','run','1.99.0','cargo','test','--no-run','--locked','--release',
            '--no-default-features','-p','wholepact-native-host','--lib','--features',
            'durable-proposal,synthetic-born-joined-qualification','--config',
            'profile.release.package.wholepact-signer.opt-level=0','--config',
            'profile.release.package.wholepact-engine.opt-level=0','--message-format=json']
        self.assertEqual(S.build_recipe(ROLE,PROFILE),expected)
        with tempfile.TemporaryDirectory() as temporary:
            target=pathlib.Path(temporary);artifact=target/'fabricated-never-executed'
            artifact.write_bytes(b'\x7fELFinert parser fixture only')
            row=dict(reason='compiler-artifact',target=dict(name='wholepact_native_host',kind=['lib']),
                profile=dict(test=True,opt_level='3',debug_assertions=False,overflow_checks=False),
                features=list(D.FEATURES),executable=str(artifact),
                manifest_path=str(S.REPO/'crates/wholepact-native-host/Cargo.toml'))
            self.assertEqual(S.select_artifact(raw(row),ROLE,target,PROFILE),artifact)
            mutants=[]
            for field,bad in [('test',False),('test',1),('opt_level','0'),
                              ('debug_assertions',True),('overflow_checks',True),('overflow_checks',0)]:
                changed=copy.deepcopy(row);changed['profile'][field]=bad;mutants.append(changed)
            for field in ('overflow_checks','debug_assertions'):
                changed=copy.deepcopy(row);del changed['profile'][field];mutants.append(changed)
            for field,bad in [('manifest_path','/wrong/Cargo.toml'),('features',[]),
                              ('target',dict(name='wholepact_native_host',kind=['bin']))]:
                mutants.append({**row,field:bad})
            missing=copy.deepcopy(row);del missing['manifest_path'];mutants.append(missing)
            for changed in mutants:
                with self.assertRaises(S.Failure):S.select_artifact(raw(changed),ROLE,target,PROFILE)
            with self.assertRaises(S.Failure):S.select_artifact(raw(row)+b'\n'+raw(row),ROLE,target,PROFILE)
            with self.assertRaises(S.Failure):S.select_artifact(b'',ROLE,target,PROFILE)
            for role in (*A.NAMES,'unknown'):
                with self.assertRaises(S.Failure):S.select_artifact(raw(row),role,target,PROFILE)



QUALIFICATION = ROOT.parent/'crates/wholepact-native-host/src/host/manual_enrollment/command/roster_publication_v2/sequential_construction_v3_qualification.rs'
LEAF = QUALIFICATION.with_suffix('')/'durable_proposal_v1/durable_result_lifecycle_v2.rs'
SAFE_SOURCE = QUALIFICATION.with_suffix('')/'safe_diagnostics_v1.rs'

def inert_failure(case, site=None, stage=True):
    site=site or ('a0_producer' if case=='durable-resume' else 'b_producer')
    reason=('stage_outcome_error' if stage else 'stage_call_error' if site in D.FAILURE_STAGE_EXPECTATIONS else
            'verification' if site in D.FAILURE_VERIFICATION_SITES else 'cleanup_unverified' if site=='temporary_cleanup' else 'io_error')
    value=dict(schema=1,case=case,callsite=site,reason=reason,
               io_kind='other',stage=None,cleanup='closed_absent')
    if stage:
        expected,mode=D.FAILURE_STAGE_EXPECTATIONS[site]
        value['stage']=dict(failure_reason='ChildExit',next=0,expected=expected,expected_process=mode,
            group_signal='SentWhileLeaderOwned',group_absence='OriginalGroupAbsentObserved',direct_child='Reaped',
            status_kind='exit',status_value=1,diagnostic_state='validated',
            private_fixed_primary=dict(operation='Checkpoint',site='HostCheckpointEntry',engine_code='NotApplicable',family='Host',cause='Permission'),
            delivery_first_failure=dict(boundary='PrivateWorkspaceCapture',outcome='BridgePermission'))
    return value

class DurableNativeFailureTests(unittest.TestCase):
    def test_exact_schema_case_sites_stage_counts_and_types(self):
        for case in CASES:
            for site in D.FAILURE_COMMON_SITES|D.FAILURE_CASE_SITES[case]:
                value=inert_failure(case,site,False)
                self.assertEqual(D.native_failure(case,raw(value)),value)
                for wrong in D.FAILURE_REASONS-{value['reason']}:
                    with self.assertRaises(D.Rejected):D.native_failure(case,raw({**value,'reason':wrong}))
            for site in set(D.FAILURE_STAGE_EXPECTATIONS)&D.FAILURE_CASE_SITES[case]:
                value=inert_failure(case,site)
                self.assertEqual(D.native_failure(case,raw(value)),value)
                expected=value['stage']['expected']
                deadline=copy.deepcopy(value);deadline['reason']='stage_deadline'
                if site in ('a2_reader','b_reader'):
                    deadline['stage']['status_value']=0
                    D.native_failure(case,raw(deadline))
                else:
                    with self.assertRaises(D.Rejected):D.native_failure(case,raw(deadline))
                for next_value in (0,expected):
                    copy_value=copy.deepcopy(value);copy_value['stage']['next']=next_value
                    D.native_failure(case,raw(copy_value))
                for field,bad in [('next',-1),('next',True),('next',expected+1),('expected',expected+1),
                    ('expected',True),('expected_process','unknown'),('failure_reason','private text')]:
                    changed=copy.deepcopy(value);changed['stage'][field]=bad
                    with self.assertRaises(D.Rejected):D.native_failure(case,raw(changed))
                for field in value['stage']:
                    changed=copy.deepcopy(value);del changed['stage'][field]
                    with self.assertRaises(D.Rejected):D.native_failure(case,raw(changed))
            value=inert_failure(case)
            other=next(c for c in CASES if c!=case)
            mutants=[{**value,k:v} for k,v in [('schema',True),('schema',2),('case',other),('callsite','private text'),
                ('callsite','b_producer' if case=='durable-resume' else 'a0_producer'),('reason','private error'),
                ('io_kind','private error'),('cleanup','private path')]]
            mutants += [{k:v for k,v in value.items() if k!=key} for key in value]
            mutants += [{**value,'extra':0},{**value,'stage':None}, {**value,'callsite':'tls_prepare'}]
            for changed in mutants:
                with self.assertRaises(D.Rejected):D.native_failure(case,raw(changed))
            for bad in (b'null',b'[]',b'NaN',b'\xff',raw(value)+b'{}',raw(value).replace(b'{',b'{"schema":1,',1)):
                with self.assertRaises(D.Rejected):D.native_failure(case,bad)

    def test_process_shapes_and_diagnostic_custody_are_not_independent(self):
        for case in CASES:
            value=inert_failure(case)
            for kind,status in [('exit',0),('exit',255),('signal',1),('signal',64),('other',None)]:
                changed=copy.deepcopy(value);changed['stage'].update(status_kind=kind,status_value=status)
                D.native_failure(case,raw(changed))
            for kind,status in [('exit',None),('exit',True),('exit',-1),('exit',256),('signal',0),('signal',65),('signal',False),('absent',0),('other',1),('private',None)]:
                changed=copy.deepcopy(value);changed['stage'].update(status_kind=kind,status_value=status)
                with self.assertRaises(D.Rejected):D.native_failure(case,raw(changed))
            for key,bad in [('group_signal','Unverified'),('group_absence','Unverified'),('direct_child','Unverified'),('status_kind','absent')]:
                changed=copy.deepcopy(value);changed['stage'][key]=bad
                if key=='status_kind':changed['stage']['status_value']=None
                with self.assertRaises(D.Rejected):D.native_failure(case,raw(changed))
                changed['stage'].update(diagnostic_state='withheld',private_fixed_primary=None,delivery_first_failure=None)
                D.native_failure(case,raw(changed))
            for reason in ('process_cleanup_unverified','expected_process_status','stage_deadline'):
                changed=copy.deepcopy(value);changed['reason']=reason
                if reason=='expected_process_status':D.native_failure(case,raw(changed))
                else:
                    with self.assertRaises(D.Rejected):D.native_failure(case,raw(changed))
                if reason=='process_cleanup_unverified':
                    changed['stage'].update(group_signal='Unverified',diagnostic_state='withheld',private_fixed_primary=None,delivery_first_failure=None)
                    D.native_failure(case,raw(changed))
                if reason=='expected_process_status':
                    changed['stage'].update(status_kind='signal',status_value=9)
                    with self.assertRaises(D.Rejected):D.native_failure(case,raw(changed))
                changed['io_kind']='timed_out'
                with self.assertRaises(D.Rejected):D.native_failure(case,raw(changed))
            for state in ('withheld','unavailable'):
                changed=copy.deepcopy(value);changed['stage']['diagnostic_state']=state
                with self.assertRaises(D.Rejected):D.native_failure(case,raw(changed))
                changed['stage']['private_fixed_primary']=None
                D.native_failure(case,raw(changed))
            changed=copy.deepcopy(value);changed['stage']['private_fixed_primary']=None
            with self.assertRaises(D.Rejected):D.native_failure(case,raw(changed))
            for key in value['stage']['private_fixed_primary']:
                changed=copy.deepcopy(value);changed['stage']['private_fixed_primary'][key]='private arbitrary'
                with self.assertRaises(D.Rejected):D.native_failure(case,raw(changed))
            for delivery in ({'boundary':'unknown','outcome':'BridgePermission'},{'boundary':'PrivateWorkspaceCapture','outcome':'Begin'},
                             {'boundary':'PrivateWorkspaceCapture','outcome':'Complete'},{'boundary':'PrivateWorkspaceCapture','outcome':'BridgePermission','secret':0}):
                changed=copy.deepcopy(value);changed['stage']['delivery_first_failure']=delivery
                with self.assertRaises(D.Rejected):D.native_failure(case,raw(changed))

    def test_marker_preserved_before_failed_summary_never_promotes_success(self):
        for case in CASES:
            failure=inert_failure(case);line=D.NATIVE_FAILURE_MARKER+raw(failure)
            for coalesced in (False,True):
                output=D.TestOutput(case)
                output.line((b'test '+CASES[case].encode()+b' ... ' if coalesced else b'')+line)
                if not coalesced:output.line(b'test '+CASES[case].encode()+b' ... FAILED')
                output.line(D.NATIVE_MARKERS[case]+raw(inert_receipt(case)))
                with self.assertRaises(D.Rejected):output.line(SUMMARY.replace(b'1 passed; 0 failed',b'0 passed; 1 failed').replace(b'ok.',b'FAILED.'))
                self.assertEqual(output.native_failure,failure)
                with self.assertRaises(D.Rejected):output.line(line)
            output=D.TestOutput(case)
            for item in [line,*native_lines(case)]:output.line(item)
            with self.assertRaises(D.Rejected):output.finish(0)
            outer=dict(schema=1,profile=PROFILE,case=case,code='native_assertion',native_receipt=inert_receipt(case),cleanup_unverified=True,native_failure=failure)
            records=D.RuntimeRecords(case,SOURCE);records(b'CI_FINANCIAL_DURABLE_FAILURE '+raw(outer))
            self.assertEqual(records.failure,outer)
            for status in (0,1):
                with self.assertRaises(D.Rejected):records.finish(status)
            other=next(c for c in CASES if c!=case)
            for bad in (None,{},inert_failure(other),{**failure,'extra':True}):
                with self.assertRaises(D.Rejected):D.RuntimeRecords(case,SOURCE)(b'CI_FINANCIAL_DURABLE_FAILURE '+raw({**outer,'native_failure':bad}))
            forged=D.candidate(case,SOURCE,inert_receipt(case));forged['native_failure']=failure
            with self.assertRaises(D.Rejected):D.validate_candidate(forged,case,SOURCE)

    def test_actual_wrapper_keeps_first_failure_when_cleanup_also_fails(self):
        case='durable-resume';failure=inert_failure(case)
        data=b'\n'.join([b'test '+CASES[case].encode()+b' ... '+D.NATIVE_FAILURE_MARKER+raw(failure),
            D.NATIVE_MARKERS[case]+raw(inert_receipt(case)),
            SUMMARY.replace(b'1 passed; 0 failed',b'0 passed; 1 failed').replace(b'ok.',b'FAILED.')])+b'\n'
        with tempfile.TemporaryDirectory() as tmp:
            path_type=pathlib.Path;root=path_type(tmp)
            process=Mock(pid=123,returncode=None);process.stdout=Mock()
            def wait(**kwargs):process.returncode=1;return 1
            process.wait.side_effect=wait
            selector=Mock();selector.__enter__=Mock(return_value=selector);selector.__exit__=Mock(return_value=False)
            selector.select.return_value=[object()]
            output=io.StringIO()
            with patch.object(D.pathlib,'Path',side_effect=lambda value:root if value=='/ci-fixture' else path_type(value)), \
                 patch.object(D.os,'getpid',return_value=1),patch.object(D.os,'getresuid',return_value=(10001,)*3), \
                 patch.object(D.os,'getresgid',return_value=(10001,)*3),patch.object(D.os,'getgroups',return_value=[]), \
                 patch.object(D.os,'getpgid',return_value=123),patch.object(D.os,'killpg',side_effect=OSError('private cleanup text')) as kill, \
                 patch.object(D.os,'read',side_effect=[data,b'']),patch.object(D.subprocess,'Popen',return_value=process), \
                 patch.object(D.selectors,'DefaultSelector',return_value=selector),contextlib.redirect_stdout(output):
                status=D.run_case(case,{'profile':PROFILE,'source_commit':SOURCE},D.time.monotonic_ns()+10_000_000_000)
            self.assertEqual(status,1);kill.assert_called_once()
            lines=output.getvalue().splitlines();self.assertEqual(len(lines),1)
            records=D.RuntimeRecords(case,SOURCE);records(lines[0].encode())
            self.assertEqual(records.failure['code'],'native_assertion');self.assertEqual(records.failure['native_failure'],failure)
            self.assertTrue(records.failure['cleanup_unverified']);self.assertNotIn('private cleanup text',output.getvalue())

    def test_worst_valid_record_and_failure_line_fit_original_cap(self):
        lengths=[]
        for case in CASES:
            for site in set(D.FAILURE_STAGE_EXPECTATIONS)&D.FAILURE_CASE_SITES[case]:
                value=inert_failure(case,site);stage=value['stage'];stage['next']=stage['expected']
                stage.update(failure_reason=max(D.FAILURE_HARNESS_REASONS,key=len),group_signal='AlreadyAbsentWhileLeaderOwned',status_value=255)
                family=max(D.PRIVATE_FIXED_FAMILIES,key=lambda f:len(f)+max(map(len,D.PRIVATE_FIXED_FAMILIES[f])))
                stage['private_fixed_primary']=dict(operation=max(D.PRIVATE_FIXED_OPERATIONS,key=len),site=max(D.PRIVATE_FIXED_SITES,key=len),
                    engine_code=max(D.PRIVATE_FIXED_ENGINE_CODES,key=len),family=family,cause=max(D.PRIVATE_FIXED_FAMILIES[family],key=len))
                stage['delivery_first_failure']=dict(boundary=max(D.FAILURE_DELIVERY_BOUNDARIES,key=len),outcome=max(D.FAILURE_DELIVERY_OUTCOMES,key=len))
                value.update(reason='stage_outcome_error',io_kind=max(D.FAILURE_IO_KINDS,key=len),cleanup=max(D.FAILURE_CLEANUP,key=len))
                D.native_failure(case,raw(value))
                lengths.append(len(D.NATIVE_FAILURE_MARKER+raw(value)))
                outer=dict(schema=1,profile=PROFILE,case=case,code=max(D.FAILURES,key=len),native_receipt=inert_receipt(case),cleanup_unverified=True,native_failure=value)
                encoded=b'CI_FINANCIAL_DURABLE_FAILURE '+raw(outer)
                D.RuntimeRecords(case,SOURCE)(encoded);lengths.append(len(encoded))
        self.assertLessEqual(max(lengths),8192);self.assertEqual(D.MAX_LINE,8192)

    def test_closed_domains_match_actual_native_and_existing_primary_validator(self):
        existing=load('ci-synthetic-output')
        for name in ('PRIVATE_FIXED_PRIMARY_FIELDS','PRIVATE_FIXED_OPERATIONS','PRIVATE_FIXED_SITES','PRIVATE_FIXED_ENGINE_CODES'):
            self.assertEqual(getattr(D,name),getattr(existing,name))
        self.assertEqual({k:set(v) for k,v in D.PRIVATE_FIXED_FAMILIES.items()}, {k:set(v) for k,v in existing.PRIVATE_FIXED_FAMILIES.items()})
        native=SAFE_SOURCE.read_text()
        boundaries=native.split('pub(super) const DELIVERY_BOUNDARIES: &[&str] = &[',1)[1].split('];',1)[0]
        self.assertEqual(D.FAILURE_DELIVERY_BOUNDARIES,set(re.findall(r'"([A-Za-z0-9_]+)"',boundaries)))
        outcomes=re.search(r'labels!\s*\{\s*Outcome\s*\{(.*?)\}\s*\}',native,re.S).group(1)
        self.assertEqual(D.FAILURE_DELIVERY_OUTCOMES,{x.strip() for x in outcomes.split(',') if x.strip()}-{'Begin','Complete'})
        shared=QUALIFICATION.read_text()
        reasons=re.search(r'enum HarnessFailureReason\s*\{(.*?)\}',shared,re.S).group(1)
        self.assertEqual(D.FAILURE_HARNESS_REASONS,{x.strip() for x in reasons.split(',') if x.strip()})
        process=(QUALIFICATION.with_suffix('')/'owned_test_process_group_v1.rs').read_text()
        for name,labels in [('GroupSignalV1',D.FAILURE_GROUP_SIGNALS),('GroupAbsenceV1',D.FAILURE_GROUP_ABSENCE),('DirectChildV1',D.FAILURE_DIRECT_CHILD)]:
            body=re.search(r'enum '+name+r'\s*\{(.*?)\}',process,re.S).group(1)
            self.assertEqual(labels,{x.strip() for x in body.split(',') if x.strip()})
        leaf=LEAF.read_text()
        count_sources={'a0_producer':('producer_inputs_v2',127),'a1_intake':('intake_inputs_v2',23),
                       'a2_reader':('reader_inputs_v2',147),'b_producer':('started_producer_inputs_v2',118)}
        for site,(function,count) in count_sources.items():
            self.assertEqual(D.FAILURE_STAGE_EXPECTATIONS[site][0],count)
            self.assertIn(f'assert_eq!({function}().len(),{count});',leaf)
        self.assertEqual(D.FAILURE_STAGE_EXPECTATIONS['b_reader'],(0,'success'))
        self.assertIn('PrivateWorkspaceStageV1::DurableResultStartedReader,&[],deadline,cutoff',leaf)
        self.assertIn('FailureSiteV2::BReader,ExpectedProcessV2::Success,0)',leaf)
        def snake(name):return re.sub(r'(?<!^)(?=[A-Z])','_',name).lower()
        actual_validation={snake(x) for x in re.findall(r'report\.enter\(FailureSiteV2::([A-Za-z0-9]+),FailureReasonV2::Verification\)',leaf)}
        self.assertEqual(D.FAILURE_VERIFICATION_SITES,actual_validation)
        for enum,labels in [('FailureSiteV2',D.FAILURE_COMMON_SITES|set().union(*D.FAILURE_CASE_SITES.values())),('FailureReasonV2',D.FAILURE_REASONS),('FailureCleanupV2',D.FAILURE_CLEANUP)]:
            body=re.search(r'enum '+enum+r'\s*\{(.*?)\}',leaf,re.S).group(1)
            self.assertEqual(labels,{snake(x.strip()) for x in body.split(',') if x.strip()})
        body=leaf.split('fn failure_io_kind_v2(',1)[1].split('fn harness_reason_v2',1)[0]
        self.assertEqual(D.FAILURE_IO_KINDS,set(re.findall(r'=>"([a-z_]+)"',body)))

    def test_actual_delivery_route_is_additive_without_financial_progress(self):
        source=QUALIFICATION.read_text().split('fn private_workspace_stage_v1(',1)[1]
        block=source.split('transcript.enable_delivery_first_failure();',1)[0].rsplit('if matches!(',1)[1]
        names=re.findall(r'PrivateWorkspaceStageV1::([A-Za-z0-9]+)',block)
        self.assertEqual(names,['DeliveryProducer','DeliveryReader','FinancialProducer','FinancialReader',
            'DurableResultProducer','DurableResultIntake','DurableResultReader','DurableResultStartedProducer','DurableResultStartedReader'])
        for variant,call in [('FinancialProducer','transcript.enable_financial_v2('),('FinancialReader','transcript.enable_financial_v2(Instant::now(), true)')]:
            match='if matches!(stage, PrivateWorkspaceStageV1::'+variant+') {'
            self.assertEqual(source.count(match),1)
            self.assertIn(call,source.split(match,1)[1].split('\n    }',1)[0])
        self.assertEqual(source.count('transcript.enable_financial_v2('),2)

if __name__ == '__main__': unittest.main()
