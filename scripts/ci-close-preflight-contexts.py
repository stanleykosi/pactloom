#!/usr/bin/env python3
"""Fixed P51 typechecks and selected maintained synthetic tests; no fullflow or artifact export."""
import importlib.util,json,os,pathlib,shutil,time
HERE=pathlib.Path(__file__).resolve().parent
spec=importlib.util.spec_from_file_location('preflight_supervisor',HERE/'ci-financial-supervisor.py');S=importlib.util.module_from_spec(spec);spec.loader.exec_module(S)
PACKAGES=('wholepact-financial-coordinator','wholepact-native-host','wholepact-authority','wholepact-financial-coordinator-origin','wholepact-signer')
SCRIPTS=('wholepact-financial-coordinator','wholepact-native-host','wholepact-financial-coordinator-origin','wholepact-signer')
FEATURES=('wholepact-financial-coordinator/coordinated-financial-runtime','wholepact-native-host/coordinated-financial-workflow-v1','wholepact-signer/coordinated-financial-workflow-v1',*(f'wholepact-authority/{x}' for x in ('coordinated-witness-financial-history','coordinated-witness-financial-continuation','coordinated-witness-financial-signing','coordinated-witness-completed-pair')))
def validate(raw,target):
    rows=[json.loads(line) for line in raw.splitlines() if line.startswith(b'{')]
    packages={};tested=set()
    for row in rows:
        if row.get('reason')!='compiler-artifact':continue
        t=row.get('target',{});manifest=row.get('manifest_path','')
        if t.get('kind')==['custom-build'] and pathlib.Path(manifest).is_relative_to(S.REPO):
            crate=pathlib.Path(manifest).parent.name
            assert crate in SCRIPTS and crate not in packages.values()
            assert t.get('name')=='build-script-build' and t.get('src_path')==str(S.REPO/'crates'/crate/'build.rs')
            packages[row['package_id']]=crate
        if row.get('profile',{}).get('test') is True and manifest in [str(S.REPO/'crates'/p/'Cargo.toml') for p in PACKAGES]:
            crate=pathlib.Path(manifest).parent.name
            binary=crate=='wholepact-financial-coordinator'
            if binary:assert sorted(row.get('features',[]))==sorted(S.A.RECIPE['artifact_features']['coordinator-observed'])
            kind=['bin'] if binary else ['lib'];source='main.rs' if binary else 'lib.rs'
            if t.get('kind')==kind and t.get('name')==(crate if binary else crate.replace('-','_')) and t.get('src_path')==str(S.REPO/'crates'/crate/'src'/source):
                tested.add(crate)
    assert set(packages.values())==set(SCRIPTS) and tested==set(PACKAGES)
    seen=set()
    for row in rows:
        if row.get('reason')!='build-script-executed':continue
        package=row.get('package_id');cfgs=row.get('cfgs');assert type(cfgs) is list
        if package not in packages:
            assert not any(c.startswith('wholepact_financial_') for c in cfgs);continue
        assert package not in seen and cfgs==list(S.A.FINANCIAL_CFGS)
        assert row.get('linked_libs')==[] and row.get('linked_paths')==[] and row.get('env')==[]
        out=pathlib.Path(row['out_dir']);assert out.is_dir() and not out.is_symlink() and out.resolve().is_relative_to(target.resolve());seen.add(package)
    assert seen==set(packages)
SIGNER_SCRIPTS=('wholepact-financial-coordinator-origin','wholepact-signer')
SIGNER_FEATURES=('authority-signing','coordinated-financial-workflow-v1','coordinated-signer-continue','durable-proposal','native-ui','pending-birth-owner-signing','wallet-review')
SIGNER_PROBES=(('VerifiedImportedCoordinatedDurableReviewSessionV1','request_admission_retained_observed_v1'),('PendingCoordinatedDurableDeliveryAdmissionV1','read_original_status_retained_observed_v1'),('CoordinatedOriginalClientV1','prepare_closed_recipient_observed_v1'),('ImportedCoordinatedDurableReviewSessionV1','await_verified_observed_v3'))
def signer_metadata(raw,target,cfgs):
    rows=[json.loads(line) for line in raw.splitlines() if line.startswith(b'{')]
    packages={};metadata=[]
    for row in rows:
        if row.get('reason')!='compiler-artifact':continue
        t=row.get('target',{});manifest=row.get('manifest_path','')
        if t.get('kind')==['custom-build'] and pathlib.Path(manifest).is_relative_to(S.REPO):
            crate=pathlib.Path(manifest).parent.name
            assert crate in SIGNER_SCRIPTS and crate not in packages.values()
            assert t.get('name')=='build-script-build' and t.get('src_path')==str(S.REPO/'crates'/crate/'build.rs')
            packages[row['package_id']]=crate
        if manifest!=str(S.REPO/'crates/wholepact-signer/Cargo.toml') or t.get('kind')==['custom-build']:continue
        assert row.get('profile',{}).get('test') is False
        assert t.get('kind')==['lib'] and t.get('name')=='wholepact_signer' and t.get('src_path')==str(S.REPO/'crates/wholepact-signer/src/lib.rs')
        assert sorted(row.get('features',[]))==list(SIGNER_FEATURES)
        files=[pathlib.Path(x) for x in row['filenames'] if x.endswith('.rmeta')]
        assert len(files)==1 and files[0].is_file() and not files[0].is_symlink() and files[0].resolve().is_relative_to(target.resolve())
        metadata.extend(files)
    assert len(metadata)==1 and set(packages.values())==set(SIGNER_SCRIPTS)
    seen=set()
    for row in rows:
        if row.get('reason')!='build-script-executed':continue
        package=row.get('package_id');actual=row.get('cfgs');assert type(actual) is list
        if package not in packages:
            assert not any(c.startswith('wholepact_financial_') for c in actual);continue
        assert package not in seen and actual==list(cfgs)
        assert row.get('linked_libs')==[] and row.get('linked_paths')==[] and row.get('env')==[]
        out=pathlib.Path(row['out_dir']);assert out.is_dir() and not out.is_symlink() and out.resolve().is_relative_to(target.resolve());seen.add(package)
    assert seen==set(packages)
    return metadata[0]
def absent_method_diagnostic(status,raw,method):
    rows=[json.loads(line) for line in raw.splitlines() if line.startswith(b'{')]
    errors=[row for row in rows if row.get('level')=='error' and row.get('code') is not None]
    assert status!=0 and len(errors)==1 and errors[0]['code']['code']=='E0599'
    assert method in errors[0]['message']
    assert all(row.get('level')!='error' or row in errors or row.get('message')=='aborting due to 1 previous error' for row in rows)
def check_signer_absence(root,env):
    target=root/'target-shared';done=[]
    for mode,artifact,profile,cfgs in [('production','coordinator-production',S.A.SEMANTIC_PROFILE,()),('pixel','coordinator-observed',S.A.PIXEL_PROFILE,S.A.FINANCIAL_CFGS[:2])]:
        selected=S.select_build_environment(env,artifact,profile)
        raw=S.checked(['rustup','run','1.99.0','cargo','check','--locked','--lib','--no-default-features','--message-format=json','-p','wholepact-signer','--features','wholepact-signer/coordinated-financial-workflow-v1'],'compile',env=selected,seconds=600,limit=32*1024*1024)
        metadata=signer_metadata(raw,target,cfgs)
        for index,(kind,method) in enumerate(SIGNER_PROBES):
            probe=root/f'signer-{mode}-{index}.rs'
            probe.write_text(f'use wholepact_signer::authority_bridge::durable_review_ipc_v3::coordinated_v1::{kind};\nfn main() {{ let _ = {kind}::{method}; }}\n')
            status,output=S.command(['rustup','run','1.99.0','rustc','--edition=2021','--error-format=json','--emit=metadata','--crate-name',f'signer_absence_{index}',str(probe),'--extern',f'wholepact_signer={metadata}','-L',f'dependency={target/"debug/deps"}','-o',str(root/f'{mode}-{index}.rmeta')],'compile',env=selected,seconds=60,limit=1024*1024)
            absent_method_diagnostic(status,output,method)
        done.append(mode)
    return done
# Exact reviewed maintained names; no caller-controlled selector.
HANDOFF_SECURITY_TESTS=(
    'consent_journal::authority::coordinated_preconstruction_v1::handoff_security_tests::handoff_mint_rejects_either_missing_original_nonce',
    'consent_journal::authority::coordinated_preconstruction_v1::handoff_security_tests::handoff_mint_rejects_either_expired_original_nonce',
    'consent_journal::authority::coordinated_preconstruction_v1::handoff_security_tests::handoff_mint_rejects_either_receipt_wall_expiry_or_rollback',
    'consent_journal::authority::coordinated_preconstruction_v1::handoff_security_tests::handoff_mint_rejects_crossed_record_references',
    'consent_journal::authority::coordinated_preconstruction_v1::handoff_security_tests::handoff_identity_requires_original_session_arc_not_visible_labels',
    'consent_journal::authority::coordinated_preconstruction_v1::handoff_security_tests::handoff_identity_rejects_generation_change',
    'consent_journal::authority::coordinated_preconstruction_v1::handoff_security_tests::handoff_identity_rejects_revoked_or_expired_session',
    'consent_journal::authority::coordinated_preconstruction_v1::handoff_security_tests::handoff_identity_requires_exact_records_including_nonce_and_transport',
    'consent_journal::authority::coordinated_preconstruction_v1::handoff_security_tests::handoff_identity_rechecks_both_receipt_origin_fields',
    'consent_journal::authority::coordinated_preconstruction_v1::handoff_security_tests::handoff_identity_rechecks_account_principal_and_enrollment_link',
    'consent_journal::authority::coordinated_preconstruction_v1::handoff_security_tests::handoff_identity_retains_original_source_absolute_ceiling',
    'consent_journal::authority::coordinated_preconstruction_v1::handoff_security_tests::handoff_identity_retains_both_accepted_review_lower_wall_bounds',
    'consent_journal::authority::coordinated_preconstruction_v1::handoff_security_tests::handoff_pair_identity_rejects_each_source_peer_generation_session_and_ref_mismatch',
    'consent_journal::authority::coordinated_preconstruction_v1::handoff_security_tests::handoff_identity_observation_never_renews_legacy_receipt120',
    'consent_journal::authority::coordinated_preconstruction_v1::handoff_security_tests::handoff_marker_consumes_enrollment_before_attempt_and_rejects_replay',
    'consent_journal::authority::coordinated_preconstruction_v1::handoff_security_tests::handoff_marker_rejects_out_of_order_manifest_and_later_enrollment',
    'consent_journal::authority::coordinated_preconstruction_v1::handoff_security_tests::handoff_marker_requires_exact_committed_enrollment_and_consumes_mismatch',
    'consent_journal::authority::coordinated_preconstruction_v1::handoff_security_tests::handoff_marker_allows_only_one_manifest_attempt_and_no_second_mint',
    'consent_journal::authority::coordinated_preconstruction_v1::handoff_security_tests::handoff_failed_mint_eligibility_does_not_erase_committed_rows',
    'consent_journal::authority::coordinated_preconstruction_v1::handoff_security_tests::handoff_capabilities_do_not_clone_deref_deserialize_or_escape_to_generic_lease',
    'consent_journal::preconstruction_lease::coordinated_v1::handoff_security_tests::handoff_purpose_identity_rejects_every_cross_purpose_even_with_same_pointer',
    'consent_journal::preconstruction_lease::coordinated_v1::handoff_security_tests::handoff_purpose_identity_rejects_every_distinct_final_pointer',
    'consent_journal::authority::durable_delivery_admission_intent_v3::coordinated_v1::handoff_chain_tests::handoff_admission_chain_rejects_each_source_ref_principal_session_digest_and_request_mismatch',
    'consent_journal::authority::durable_delivery_admission_intent_v3::coordinated_v1::handoff_chain_tests::handoff_admission_chain_rejects_each_actor_role_and_session_mismatch',
    'consent_journal::authority::durable_delivery_admission_intent_v3::coordinated_v1::handoff_chain_tests::handoff_admission_chain_rejects_changed_source_material_and_service_wall_ceilings',
    'consent_journal::authority::durable_delivery_admission_intent_v3::coordinated_v1::handoff_chain_tests::handoff_admission_chain_rejects_changed_original_source_channel_material_service_deadlines',
    'account::birth::enrollment::roster_v2::durable_entry_v1::prepared_delivery_v3::coordinated_source_entry_v1::coordinated_delivery_source_v1::coordinated_admission_v1::handoff_chain_tests::handoff_admit_read_chain_rejects_each_received_and_owner_binding_mismatch',
    'account::birth::enrollment::roster_v2::durable_entry_v1::prepared_delivery_v3::coordinated_source_entry_v1::coordinated_delivery_source_v1::coordinated_admission_v1::handoff_chain_tests::handoff_admit_read_chain_rejects_each_actor_role_and_session_mismatch',
    'account::birth::enrollment::roster_v2::durable_entry_v1::prepared_delivery_v3::coordinated_source_entry_v1::coordinated_delivery_source_v1::coordinated_admission_v1::handoff_chain_tests::handoff_admit_read_chain_rejects_rebound_prepare_refs_session_pair_and_material',
    'account::birth::enrollment::roster_v2::durable_entry_v1::prepared_delivery_v3::coordinated_source_entry_v1::coordinated_delivery_source_v1::coordinated_admission_v1::handoff_chain_tests::handoff_admit_read_chain_rejects_changed_original_source_channel_material_service_caps',
    'consent_journal::preconstruction_lease::durable_receipt_tests::current_receipts_pass_but_stale_history_does_not_approve_new_disclosure',
    'consent_journal::preconstruction_lease::durable_receipt_tests::both_receipts_require_exact_current_session_generation_epoch_and_measurement',
    'consent_journal::preconstruction_lease::durable_receipt_tests::both_receipts_require_an_issued_nonce_not_just_matching_origin_metadata',
    'consent_journal::preconstruction_lease::durable_receipt_tests::both_receipts_require_the_original_monotonic_review_window',
    'consent_journal::preconstruction_lease::durable_receipt_tests::earlier_success_does_not_renew_either_original_monotonic_receipt_window',
    'consent_journal::preconstruction_lease::durable_receipt_tests::both_receipts_require_current_wall_clock_window',
    'consent_journal::authority::coordinated_preconstruction_v1::tests::coordinated_fresh_receipt_rejects_historical_session',
    'consent_journal::authority::coordinated_preconstruction_v1::tests::coordinated_fresh_receipt_visible_session_relabel_cannot_mint_nonce',
    'consent_journal::authority::coordinated_preconstruction_v1::tests::coordinated_fresh_receipt_original_monotonic_window_cannot_renew',
    'account::birth::enrollment::roster_v2::durable_entry_v1::prepared_delivery_v3::coordinated_source_entry_v1::coordinated_delivery_source_v1::material_selection_handoff_tests::accepted_selection_preserves_absolute_material_not_old_receipt_window',
    'account::birth::enrollment::roster_v2::durable_entry_v1::prepared_delivery_v3::coordinated_source_entry_v1::coordinated_delivery_source_v1::material_selection_handoff_tests::material_selection_intersects_original_source_and_channel',
    'account::birth::enrollment::roster_v2::durable_entry_v1::prepared_delivery_v3::coordinated_source_entry_v1::coordinated_delivery_source_v1::material_selection_handoff_tests::material_selection_does_not_refresh_on_later_observation',
    'account::birth::enrollment::roster_v2::durable_entry_v1::prepared_delivery_v3::coordinated_source_entry_v1::coordinated_delivery_source_v1::material_selection_handoff_tests::material_selection_rejects_wall_rollback_and_absolute_expiry',
    'account::birth::enrollment::roster_v2::durable_entry_v1::prepared_delivery_v3::coordinated_source_entry_v1::coordinated_delivery_source_v1::material_selection_handoff_tests::material_selection_refuses_expired_or_unstarted_originals',
)
def signer_test_executable(raw,target):
    rows=[json.loads(line) for line in raw.splitlines() if line.startswith(b'{')]
    packages={};executables=[]
    for row in rows:
        if row.get('reason')!='compiler-artifact':continue
        t=row.get('target',{});manifest=row.get('manifest_path','')
        if t.get('kind')==['custom-build'] and pathlib.Path(manifest).is_relative_to(S.REPO):
            crate=pathlib.Path(manifest).parent.name
            assert crate in SIGNER_SCRIPTS and crate not in packages.values()
            assert t.get('name')=='build-script-build' and t.get('src_path')==str(S.REPO/'crates'/crate/'build.rs')
            packages[row['package_id']]=crate
        if manifest!=str(S.REPO/'crates/wholepact-signer/Cargo.toml') or row.get('executable') is None:continue
        assert row.get('profile',{}).get('test') is True
        assert t.get('kind')==['lib'] and t.get('name')=='wholepact_signer' and t.get('src_path')==str(S.REPO/'crates/wholepact-signer/src/lib.rs')
        assert sorted(row.get('features',[]))==list(SIGNER_FEATURES)
        executable=pathlib.Path(row['executable'])
        assert executable.is_file() and not executable.is_symlink() and executable.resolve().is_relative_to(target.resolve())
        assert str(executable) in row.get('filenames',[])
        executables.append(executable)
    assert len(executables)==1 and set(packages.values())==set(SIGNER_SCRIPTS)
    seen=set()
    for row in rows:
        if row.get('reason')!='build-script-executed':continue
        package=row.get('package_id');cfgs=row.get('cfgs');assert type(cfgs) is list
        if package not in packages:
            assert not any(c.startswith('wholepact_financial_') for c in cfgs);continue
        assert package not in seen and cfgs==list(S.A.FINANCIAL_CFGS)
        assert row.get('linked_libs')==[] and row.get('linked_paths')==[] and row.get('env')==[]
        out=pathlib.Path(row['out_dir']);assert out.is_dir() and not out.is_symlink() and out.resolve().is_relative_to(target.resolve());seen.add(package)
    assert seen==set(packages)
    return executables[0]
def run_handoff_security_tests(root,env):
    assert HANDOFF_SECURITY_TESTS and len(set(HANDOFF_SECURITY_TESTS))==len(HANDOFF_SECURITY_TESTS)
    selected=S.select_build_environment(env,'coordinator-observed',S.A.SEMANTIC_PROFILE)
    args=['rustup','run','1.99.0','cargo','test','--locked','--lib','--no-run','--no-default-features','--message-format=json','-p','wholepact-signer','--features','wholepact-signer/coordinated-financial-workflow-v1']
    raw=S.checked(args,'compile',env=selected,seconds=900,limit=32*1024*1024)
    executable=signer_test_executable(raw,root/'target-shared')
    deadline=time.monotonic()+180
    def fixed(args):
        remaining=deadline-time.monotonic();assert remaining>0
        return S.checked(args,'compile',env=selected,seconds=min(30,remaining),limit=1024*1024).decode('utf-8',errors='strict')
    # Verify the entire fixed selection before executing the first test.
    for name in HANDOFF_SECURITY_TESTS:
        listing=fixed([str(executable),'--list','--exact',name])
        assert [line for line in listing.splitlines() if line.endswith(': test')]==[name+': test']
    for name in HANDOFF_SECURITY_TESTS:
        output=fixed([str(executable),'--exact',name,'--test-threads=1'])
        assert 'test result: ok. 1 passed; 0 failed; 0 ignored;' in output
        print('CI_HANDOFF_SECURITY_TEST '+json.dumps(dict(name=name,passed=True,ignored=0),sort_keys=True))
    print('CI_HANDOFF_SECURITY_TESTS '+json.dumps(dict(actual_maintained_tests=len(HANDOFF_SECURITY_TESTS),passed=True,genuine_pair_or_final_fixture=False,fullflow=False),sort_keys=True))
    return len(HANDOFF_SECURITY_TESTS)
def main():
    root=pathlib.Path(os.environ['PREFLIGHT_ROOT']).resolve();assert root.is_dir()
    env=dict(PATH=os.environ['PATH'],HOME=str(root/'home'),CARGO_HOME=str(root/'cargo'),CARGO_TARGET_DIR=str(root/'target-shared'),CARGO_BUILD_JOBS='3',CARGO_INCREMENTAL='0',RUSTUP_HOME=os.environ['RUSTUP_HOME'],GIT_CONFIG_NOSYSTEM='1',GIT_CONFIG_GLOBAL='/dev/null',GIT_TERMINAL_PROMPT='0')
    sha=os.environ['SOURCE_COMMIT'];S.exact_source(sha)
    try:
        env=S.encrypted_build_environment(root,env)
        selected=S.select_build_environment(env,'coordinator-observed',S.A.SEMANTIC_PROFILE)
        args=['rustup','run','1.99.0','cargo','check','--locked','--tests','--no-default-features','--message-format=json']
        for package in PACKAGES:args+=['-p',package]
        args+=['--features',','.join(FEATURES)]
        raw=S.checked(args,'compile',env=selected,seconds=900,limit=32*1024*1024)
        validate(raw,root/'target-shared');executed=run_handoff_security_tests(root,env);absence=check_signer_absence(root,env);S.exact_source(sha)
        print('CI_CLOSE_PREFLIGHT_CONTEXTS '+json.dumps(dict(schema_version=2,actual_test_contexts=list(PACKAGES),actual_semantic_script_crates=list(SCRIPTS),typecheck_passed=True,signer_observed_api_absent_profiles=absence,selected_maintained_tests_executed=executed,full_native_execution=False,fullflow=False),sort_keys=True))
    except S.Failure as error:
        # Pre-credential compiler text only; same bounded sanitizer as fresh build.
        print('CI_CLOSE_PREFLIGHT_FAILURE '+json.dumps(dict(stage=error.stage,check=error.check,**S.build_failure_tail(error.output)),sort_keys=True))
        raise
    finally:
        # This exact temporary prefix was created exclusively above; never a source path.
        shutil.rmtree(root/'sqlcipher',ignore_errors=True)
if __name__=='__main__':main()
