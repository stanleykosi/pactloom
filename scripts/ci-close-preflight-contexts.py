#!/usr/bin/env python3
"""Fixed P59 essential handoff composition and staged runtime and selected maintained synthetic tests; no fullflow or artifact export."""
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
# Actual pinned egui scheduling tests in the existing Coordinator binary.
# This is a headless test process, not a financial/native runtime activation.
REPAINT_TESTS=(
    'financial_source_ui::repaint_tests::quiet_retirement_poll_requires_in_pass_repaint',
    'financial_source_ui::repaint_tests::draw_poll_request_precedes_every_early_return',
)
COORDINATOR_DIAGNOSTIC_TESTS=('financial_source_driver::history_retirement_detail_tests::retirement_handoff_observation_preserves_operation_and_original_io_error',)
SELECTOR_EXPORT_TESTS=('financial_source_ui::selector_export_tests::export_payloads_reach_focused_textedit_only_after_native_gate', 'financial_source_ui::selector_export_tests::export_input_gate_denies_wrong_phase_focus_revocation_host_and_missing_selector', 'financial_source_ui::selector_export_tests::export_payload_bounds_prevent_normalization_and_preserve_path_limit', 'financial_source_ui::selector_export_tests::export_routing_is_bound_to_native_fields_and_postpass_scrub')
ADMISSION_SCROLL_TESTS=('financial_source_ui::admission_scroll_tests::paired_review_scroll_areas_keep_independent_native_state', 'financial_source_ui::admission_scroll_tests::review_completion_requires_eligible_visible_end', 'financial_source_ui::admission_scroll_tests::paired_review_ids_and_completion_are_bound_to_production')
WITNESS_FIRST_FAILURE_TESTS=('financial_source_driver::reported_witness_failure_tests::authenticated_report_projection_retains_every_finite_stage_class_and_peer',)
SIGNING_RETIREMENT_UI_TESTS=('financial_source_ui::signing_retirement_action_tests::signing_retirement_requires_actual_commit_and_fresh_explicit_action',)
def coordinator_test_executable(raw,target):
    rows=[json.loads(line) for line in raw.splitlines() if line.startswith(b'{')]
    packages={};executables=[]
    for row in rows:
        if row.get('reason')!='compiler-artifact':continue
        t=row.get('target',{});manifest=row.get('manifest_path','')
        if t.get('kind')==['custom-build'] and pathlib.Path(manifest).is_relative_to(S.REPO):
            crate=pathlib.Path(manifest).parent.name
            assert crate in SCRIPTS and crate not in packages.values()
            assert t.get('name')=='build-script-build' and t.get('src_path')==str(S.REPO/'crates'/crate/'build.rs')
            packages[row['package_id']]=crate
        if manifest!=str(S.REPO/'crates/wholepact-financial-coordinator/Cargo.toml') or row.get('executable') is None:continue
        assert row.get('profile',{}).get('test') is True
        assert t.get('kind')==['bin'] and t.get('name')=='wholepact-financial-coordinator' and t.get('src_path')==str(S.REPO/'crates/wholepact-financial-coordinator/src/main.rs')
        assert sorted(row.get('features',[]))==sorted(S.A.RECIPE['artifact_features']['coordinator-observed'])
        executable=pathlib.Path(row['executable'])
        assert executable.is_file() and not executable.is_symlink() and executable.resolve().is_relative_to(target.resolve())
        assert str(executable) in row.get('filenames',[])
        executables.append(executable)
    assert len(executables)==1 and set(packages.values())==set(SCRIPTS)
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
def run_coordinator_tests(root,env):
    assert len(REPAINT_TESTS)==2 and len(set(REPAINT_TESTS))==2
    assert len(COORDINATOR_DIAGNOSTIC_TESTS)==1
    assert len(SELECTOR_EXPORT_TESTS)==4
    assert len(ADMISSION_SCROLL_TESTS)==3
    assert len(WITNESS_FIRST_FAILURE_TESTS)==1
    assert len(SIGNING_RETIREMENT_UI_TESTS)==1
    names=REPAINT_TESTS+COORDINATOR_DIAGNOSTIC_TESTS+SELECTOR_EXPORT_TESTS+ADMISSION_SCROLL_TESTS+WITNESS_FIRST_FAILURE_TESTS+SIGNING_RETIREMENT_UI_TESTS
    assert len(set(names))==12
    selected=S.select_build_environment(env,'coordinator-observed',S.A.SEMANTIC_PROFILE)
    args=['rustup','run','1.99.0','cargo','test','--locked','--bin','wholepact-financial-coordinator','--no-run','--no-default-features','--message-format=json','-p','wholepact-financial-coordinator','--features',','.join(S.A.RECIPE['artifact_features']['coordinator-observed'])]
    raw=S.checked(args,'compile',env=selected,seconds=900,limit=32*1024*1024)
    executable=coordinator_test_executable(raw,root/'target-shared')
    deadline=time.monotonic()+60
    def fixed(args):
        remaining=deadline-time.monotonic();assert remaining>0
        return S.checked(args,'compile',env=selected,seconds=min(30,remaining),limit=1024*1024).decode('utf-8',errors='strict')
    for name in names:
        listing=fixed([str(executable),'--list','--exact',name])
        assert [line for line in listing.splitlines() if line.endswith(': test')]==[name+': test']
    for name in names:
        output=fixed([str(executable),'--exact',name,'--test-threads=1'])
        assert 'test result: ok. 1 passed; 0 failed; 0 ignored;' in output
        marker='CI_REPAINT_TEST ' if name in REPAINT_TESTS else 'CI_RETIREMENT_HANDOFF_TEST ' if name in COORDINATOR_DIAGNOSTIC_TESTS else 'CI_SELECTOR_EXPORT_TEST ' if name in SELECTOR_EXPORT_TESTS else 'CI_ADMISSION_SCROLL_TEST ' if name in ADMISSION_SCROLL_TESTS else 'CI_WITNESS_FIRST_FAILURE_TEST ' if name in WITNESS_FIRST_FAILURE_TESTS else 'CI_SIGNING_RETIREMENT_UI_TEST '
        print(marker+json.dumps(dict(name=name,passed=True,ignored=0),sort_keys=True))
    print('CI_REPAINT_TESTS '+json.dumps(dict(actual_maintained_tests=len(REPAINT_TESTS),passed=True,headless_egui=True,fullflow=False),sort_keys=True))
    print('CI_RETIREMENT_HANDOFF_TESTS '+json.dumps(dict(actual_maintained_tests=len(COORDINATOR_DIAGNOSTIC_TESTS),passed=True,fullflow=False),sort_keys=True))
    print('CI_SELECTOR_EXPORT_TESTS '+json.dumps(dict(actual_maintained_tests=len(SELECTOR_EXPORT_TESTS),passed=True,headless_egui=True,fullflow=False),sort_keys=True))
    print('CI_ADMISSION_SCROLL_TESTS '+json.dumps(dict(actual_maintained_tests=len(ADMISSION_SCROLL_TESTS),passed=True,headless_egui=True,fullflow=False),sort_keys=True))
    print('CI_WITNESS_FIRST_FAILURE_TESTS '+json.dumps(dict(actual_maintained_tests=len(WITNESS_FIRST_FAILURE_TESTS),passed=True,fullflow=False),sort_keys=True))
    print('CI_SIGNING_RETIREMENT_UI_TESTS '+json.dumps(dict(actual_maintained_tests=len(SIGNING_RETIREMENT_UI_TESTS),passed=True,fullflow=False),sort_keys=True))
    return len(names)

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
    'native_ui::runtime::financial_v1::coordinated_v3_delivery::coordinated_delivery_admission_v1::ready_disconnect_tests::ready_disconnect_preserves_pending_worker_error_and_panic_without_fabricating_ready',
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
    'financial_ci_actor::admit_read_observation_tests::borrowed_detail_outside_owned_scope_is_unavailable',
    'financial_ci_actor::admit_read_observation_tests::owned_scope_first_detail_wins_and_success_discards_it',
    'financial_ci_actor::admit_read_observation_tests::nested_owned_scope_restores_exact_parent_detail',
    'financial_ci_actor::admit_read_observation_tests::unwind_restores_scope_without_latching_or_closing',
    'financial_ci_actor::admit_read_observation_tests::details_do_not_cross_worker_threads',
    'financial_ci_actor::admit_read_observation_tests::original_authority_error_variant_classification_is_exact',
    'native_ui::runtime::financial_v1::coordinated_driver::financial_tail_v1::financial_worker_observation_tests::actual_join_preserves_worker_error_identity_and_success',
    'native_ui::runtime::financial_v1::coordinated_driver::financial_tail_v1::financial_worker_observation_tests::actual_join_panic_remains_uncertain_without_retry',
    'native_ui::witness_workspace::financial_continuation_v1::coordinated_admit_v1::tests::failed_admit_observation_retains_actual_cause_and_transport_boundary',
    'financial_ci_actor::admit_transport_plain_observation_tests::plain_admission_result_retains_success_and_original_error_variants',
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
FIXTURE_TARGETS={
    'authority':('wholepact-authority',('born-offline-witness-owner','default','native-witness-owner','offline-witness-owner','pending-birth-foundation','synthetic-qualification'),('wholepact-native-host','wholepact-signer'),(
        'native_witness_owner::window::ephemeral_fixture_v1::coordinated_history_lifetime_v1::tests::fixed_service_survives_121_without_renewing_original_cutoff',
        'native_witness_owner::window::ephemeral_fixture_v1::coordinated_history_lifetime_v1::tests::original_source_and_actual_policy_caps_only_narrow',
        'native_witness_owner::window::ephemeral_fixture_v1::coordinated_history_lifetime_v1::tests::expired_zero_or_oversized_original_cutoff_is_refused',
        'native_witness_owner::window::ephemeral_fixture_v1::coordinated_history_lifetime_v1::tests::wrong_owner_and_owner_drop_revoke_existing_scope',
        'native_witness_owner::window::ephemeral_fixture_v1::coordinated_history_lifetime_v1::tests::wall_rollback_and_expiry_refuse_without_refresh',
        'native_witness_owner::window::ephemeral_fixture_v1::coordinated_history_lifetime_v1::tests::later_stage_wall_drift_cannot_refresh_narrower_policy_cap',
        'native_witness_owner::window::ephemeral_fixture_v1::coordinated_history_lifetime_v1::tests::late_stage_cannot_restart_expired_fixture_or_source',
        'native_witness_owner::window::ephemeral_fixture_v1::acceptance_gate_tests::sealed_synthetic_server_gate_never_calls_accept_or_resumes',
        'native_witness_owner::window::ephemeral_fixture_v1::acceptance_gate_tests::sealing_synthetic_server_gate_never_renews_expired_or_stopped_owner',
        'transport::history_diagnostics_v1::tests::pure_flow_frame_first_error_and_returned_error_remain_independent',
        'journal::durable_financial_continuation_journal_v1::tests::coordinated_final_stamp_uses_financial_profile_without_weakening_replay',
        'journal::durable_financial_continuation_journal_v1::tests::coordinated_final_stamp_is_bound_to_the_post_append_phase',
    )),
    'pristine-host':('wholepact-native-host',('durable-proposal','financial-runtime','manual-admission','synthetic-born-joined-qualification'),('wholepact-native-host','wholepact-signer'),(
        'host::manual_enrollment::command::roster_publication_v2::sequential_construction_v3::qualification::durable_proposal_v1::coordinated_external_witness_v1::request_selector_tests::exact_second_owner_selector_parses_without_creating_permission',
        'host::manual_enrollment::command::roster_publication_v2::sequential_construction_v3::qualification::durable_proposal_v1::coordinated_external_witness_v1::request_selector_tests::owner_one_request_cannot_be_relabelled_for_owner_two',
        'host::manual_enrollment::command::roster_publication_v2::sequential_construction_v3::qualification::durable_proposal_v1::coordinated_external_witness_v1::request_selector_tests::request_bytes_cannot_change_under_retained_commitment',
        'host::manual_enrollment::command::roster_publication_v2::sequential_construction_v3::qualification::durable_proposal_v1::coordinated_external_witness_v1::request_selector_tests::selector_rejects_wrong_profile_unknown_fields_and_oversize_request',
        'host::manual_enrollment::command::roster_publication_v2::sequential_construction_v3::qualification::durable_proposal_v1::coordinated_external_witness_v1::tests::request_selector_is_closed_and_is_not_a_permission',
        'host::manual_enrollment::command::roster_publication_v2::sequential_construction_v3::qualification::durable_proposal_v1::coordinated_external_witness_v1::tests::external_observation_has_no_request_or_grant_payload',
        'host::manual_enrollment::command::roster_publication_v2::sequential_construction_v3::qualification::durable_proposal_v1::coordinated_full_fixture_v1::tests::metadata_requires_original_hash_shape',
        'host::manual_enrollment::command::roster_publication_v2::sequential_construction_v3::qualification::durable_proposal_v1::coordinated_full_fixture_v1::tests::source_metadata_is_closed',
    )),
}
def fixture_test_executable(raw,target,kind):
    assert kind in FIXTURE_TARGETS
    crate,features,scripts,_=FIXTURE_TARGETS[kind]
    rows=[json.loads(line) for line in raw.splitlines() if line.startswith(b'{')]
    packages={};executables=[]
    for row in rows:
        if row.get('reason')!='compiler-artifact':continue
        t=row.get('target',{});manifest=row.get('manifest_path','')
        if t.get('kind')==['custom-build'] and pathlib.Path(manifest).is_relative_to(S.REPO):
            script_crate=pathlib.Path(manifest).parent.name
            assert script_crate in scripts and script_crate not in packages.values()
            assert t.get('name')=='build-script-build' and t.get('src_path')==str(S.REPO/'crates'/script_crate/'build.rs')
            packages[row['package_id']]=script_crate
        if manifest!=str(S.REPO/'crates'/crate/'Cargo.toml') or row.get('executable') is None:continue
        assert row.get('profile',{}).get('test') is True
        assert t.get('kind')==['lib'] and t.get('name')==crate.replace('-','_') and t.get('src_path')==str(S.REPO/'crates'/crate/'src/lib.rs')
        assert sorted(row.get('features',[]))==list(features)
        executable=pathlib.Path(row['executable'])
        assert executable.is_file() and not executable.is_symlink() and executable.resolve().is_relative_to(target.resolve())
        assert str(executable) in row.get('filenames',[])
        executables.append(executable)
    assert len(executables)==1 and set(packages.values())==set(scripts)
    seen=set()
    for row in rows:
        if row.get('reason')!='build-script-executed':continue
        package=row.get('package_id');cfgs=row.get('cfgs');assert type(cfgs) is list
        if package not in packages:
            assert not any(c.startswith('wholepact_financial_') for c in cfgs);continue
        assert package not in seen and cfgs==[]
        assert row.get('linked_libs')==[] and row.get('linked_paths')==[] and row.get('env')==[]
        out=pathlib.Path(row['out_dir']);assert out.is_dir() and not out.is_symlink() and out.resolve().is_relative_to(target.resolve());seen.add(package)
    assert seen==set(packages)
    return executables[0]
def run_fixture_lifetime_tests(root,env):
    selected=S.select_build_environment(env,'pristine-setup',S.A.SEMANTIC_PROFILE)
    for _,_,_,names in FIXTURE_TARGETS.values():
        assert names and len(set(names))==len(names)
    args=['rustup','run','1.99.0','cargo','test','--locked','--lib','--no-run','--no-default-features','--message-format=json','-p','wholepact-native-host','-p','wholepact-authority','--features','wholepact-native-host/durable-proposal,wholepact-native-host/synthetic-born-joined-qualification']
    raw=S.checked(args,'compile',env=selected,seconds=900,limit=32*1024*1024)
    executables={kind:fixture_test_executable(raw,root/'target-shared',kind) for kind in FIXTURE_TARGETS}
    deadline=time.monotonic()+120
    def fixed(args):
        remaining=deadline-time.monotonic();assert remaining>0
        return S.checked(args,'compile',env=selected,seconds=min(30,remaining),limit=1024*1024).decode('utf-8',errors='strict')
    entries=[(kind,name) for kind,(_,_,_,names) in FIXTURE_TARGETS.items() for name in names]
    # Both targets' full fixed selections must exist before any test execution.
    for kind,name in entries:
        listing=fixed([str(executables[kind]),'--list','--exact',name])
        assert [line for line in listing.splitlines() if line.endswith(': test')]==[name+': test']
    for kind,name in entries:
        output=fixed([str(executables[kind]),'--exact',name,'--test-threads=1'])
        assert 'test result: ok. 1 passed; 0 failed; 0 ignored;' in output
        print('CI_SERVICE_LIFETIME_TEST '+json.dumps(dict(target=kind,name=name,passed=True,ignored=0),sort_keys=True))
    for kind,(_,_,_,names) in FIXTURE_TARGETS.items():
        print('CI_SERVICE_LIFETIME_TESTS '+json.dumps(dict(target=kind,actual_maintained_tests=len(names),passed=True,full_fixture_execution=False,fullflow=False),sort_keys=True))
    return len(entries)
INTENT_FEATURES=('authority-signing','coordinated-financial-workflow-v1','coordinated-signer-continue','durable-proposal','native-ui','pending-birth-owner-signing','synthetic-qualification','wallet-review')
INTENT_VALIDATION_TESTS=(
    'consent_journal::authority::durable_delivery_admission_intent_v3::coordinated_v1::full_intent_validation_tests::complete_intent_accepts_fresh_admit_read_after_prepare_read_expiry',
    'consent_journal::authority::durable_delivery_admission_intent_v3::coordinated_v1::full_intent_validation_tests::complete_intent_rejects_individual_envelope_lineage_mismatches',
    'consent_journal::authority::durable_delivery_admission_intent_v3::coordinated_v1::full_intent_validation_tests::complete_intent_rejects_original_ceiling_and_window_violations',
    'consent_journal::authority::durable_delivery_admission_intent_v3::coordinated_v1::full_intent_validation_tests::complete_intent_nested_requests_cannot_be_rebound_around_lineage',
    'consent_journal::authority::durable_delivery_admission_intent_v3::coordinated_v1::full_intent_validation_tests::complete_intent_retention_commits_review_and_preserves_action_deadline',
    'consent_journal::authority::durable_delivery_admission_intent_v3::coordinated_v1::full_intent_validation_tests::complete_intent_original_rows_reject_valid_envelope_wrong_source_lineage',
    'consent_journal::authority::durable_delivery_admission_intent_v3::coordinated_v1::full_intent_validation_tests::complete_intent_rejects_legacy_generation_rows_without_relabeling',
    'consent_journal::authority::durable_delivery_admission_intent_v3::coordinated_v1::full_intent_validation_tests::complete_intent_encrypted_retained_reader_binds_canonical_row_columns',
    'consent_journal::authority::durable_delivery_admission_intent_v3::coordinated_v1::full_intent_validation_tests::diagnostic_stage_tests::actual_complete_review_and_original_rows_success_leave_no_detail',
    'consent_journal::authority::durable_delivery_admission_intent_v3::coordinated_v1::full_intent_validation_tests::diagnostic_stage_tests::actual_complete_review_nested_and_shape_failures_select_finite_detail',
    'consent_journal::authority::durable_delivery_admission_intent_v3::coordinated_v1::full_intent_validation_tests::diagnostic_stage_tests::actual_complete_review_or_groups_select_ceiling_binding_and_material_detail',
    'consent_journal::authority::durable_delivery_admission_intent_v3::coordinated_v1::full_intent_validation_tests::diagnostic_stage_tests::actual_original_row_failures_select_exact_lineage_stage_and_original_class',
    'consent_journal::authority::durable_delivery_admission_intent_v3::coordinated_v1::full_intent_validation_tests::diagnostic_stage_tests::actual_validator_first_detail_survives_outer_fallback_and_restores_scope',
    'consent_journal::authority::durable_delivery_admission_intent_v3::coordinated_v1::full_intent_validation_tests::diagnostic_stage_tests::actual_connection_identity_error_keeps_original_journal_conversion',
    'consent_journal::authority::durable_delivery_admission_intent_v3::coordinated_v1::full_intent_validation_tests::diagnostic_stage_tests::actual_transaction_identity_error_keeps_original_journal_conversion',
    'consent_journal::authority::durable_delivery_admission_intent_v3::coordinated_v1::full_intent_validation_tests::transport_identity_tests::distinct_observed_and_original_process_labels_require_canonical_current_rows',
    'consent_journal::authority::durable_delivery_admission_intent_v3::coordinated_v1::full_intent_validation_tests::retained_report_tests::complete_prepared_display_reproduces_retained_and_admit_size_boundaries',
    'consent_journal::authority::durable_delivery_admission_intent_v3::coordinated_v1::full_intent_validation_tests::downstream_composition_tests::complete_continue_projection_preserves_request_and_fits_full_packet',
    'consent_journal::authority::durable_delivery_admission_intent_v3::coordinated_v1::full_intent_validation_tests::downstream_composition_tests::complete_sign_projection_preserves_lower_display_and_original_wallet_join',
    'consent_journal::authority::durable_delivery_admission_intent_v3::coordinated_v1::full_intent_validation_tests::downstream_composition_tests::complete_return_projection_preserves_original_host_result_and_full_packet',
    'financial_ci_actor::admit_transport_observation_tests::checked_admission_stages_and_callback_precedence_are_finite',
)
def intent_test_executable(raw,target):
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
        assert sorted(row.get('features',[]))==list(INTENT_FEATURES)
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
REPORT_MEASUREMENT_TEST='consent_journal::authority::durable_delivery_admission_intent_v3::coordinated_v1::full_intent_validation_tests::retained_report_tests::complete_prepared_display_reproduces_retained_and_admit_size_boundaries'
REPORT_MEASUREMENT_MARKER='COORDINATED_RETAINED_REPORT_SIZE_V2 '
REPORT_LENGTHS=('input_id_bytes','pretty_display_bytes','compact_display_bytes','request_json_bytes','pretty_facts_bytes','compact_facts_bytes','pretty_presentation_bytes','compact_presentation_bytes','pretty_packet_bytes','compact_packet_bytes')
REPORT_VALIDATIONS=('material_input_id','pretty_report_valid','compact_report_valid','pretty_facts_valid','compact_facts_valid','pretty_presentation_valid','compact_presentation_valid')
def report_measurement(output):
    # Validate the complete finite pair before any measurement leaves the test.
    assert output.count(REPORT_MEASUREMENT_MARKER)==2
    lines=[line for line in output.splitlines() if REPORT_MEASUREMENT_MARKER in line]
    assert len(lines)==2
    def pairs(items):
        result={}
        for key,value in items:
            assert key not in result
            result[key]=value
        return result
    values=[]
    for line in lines:
        prefix,raw=line.split(REPORT_MEASUREMENT_MARKER,1)
        assert prefix in ('','test '+REPORT_MEASUREMENT_TEST+' ... ')
        assert len(raw.encode('utf-8'))<=2048
        try:value=json.loads(raw,object_pairs_hook=pairs)
        except (ValueError,UnicodeError):raise AssertionError('measurement_schema') from None
        assert type(value) is dict and set(value)==set(REPORT_LENGTHS+REPORT_VALIDATIONS)
        assert all(type(value[k]) is int and 0<=value[k]<=2*1024*1024 for k in REPORT_LENGTHS)
        assert all(type(value[k]) is bool for k in REPORT_VALIDATIONS)
        values.append(value)
    assert {v['material_input_id'] for v in values}=={False,True}
    return sorted(values,key=lambda v:v['material_input_id'])

COMPOSITION_MEASUREMENT_TESTS={'consent_journal::authority::durable_delivery_admission_intent_v3::coordinated_v1::full_intent_validation_tests::downstream_composition_tests::complete_continue_projection_preserves_request_and_fits_full_packet': ('continue',), 'consent_journal::authority::durable_delivery_admission_intent_v3::coordinated_v1::full_intent_validation_tests::downstream_composition_tests::complete_sign_projection_preserves_lower_display_and_original_wallet_join': ('sign_lower', 'sign'), 'consent_journal::authority::durable_delivery_admission_intent_v3::coordinated_v1::full_intent_validation_tests::downstream_composition_tests::complete_return_projection_preserves_original_host_result_and_full_packet': ('return_read', 'return_exact')}
COMPOSITION_MEASUREMENT_MARKER='COORDINATED_COMPOSITION_SIZE_V1 '
COMPOSITION_LENGTHS=('display_bytes','request_json_bytes','facts_bytes','presentation_bytes','packet_bytes')
def composition_measurement(name,output,*,complete):
    expected=COMPOSITION_MEASUREMENT_TESTS[name]
    count=output.count(COMPOSITION_MEASUREMENT_MARKER)
    assert 0<count<=len(expected) and (not complete or count==len(expected))
    lines=[line for line in output.splitlines() if COMPOSITION_MEASUREMENT_MARKER in line]
    assert len(lines)==count
    def pairs(items):
        result={}
        for key,value in items:
            assert key not in result
            result[key]=value
        return result
    values=[]
    for line in lines:
        prefix,raw=line.split(COMPOSITION_MEASUREMENT_MARKER,1)
        assert prefix in ('','test '+name+' ... ') and len(raw.encode('utf-8'))<=1024
        try:value=json.loads(raw,object_pairs_hook=pairs)
        except (ValueError,UnicodeError):raise AssertionError('composition_measurement_schema') from None
        assert type(value) is dict and set(value)==set(COMPOSITION_LENGTHS+('stage',))
        assert type(value['stage']) is str
        assert all(type(value[k]) is int and 0<=value[k]<=2*1024*1024 for k in COMPOSITION_LENGTHS)
        values.append(value)
    assert tuple(v['stage'] for v in values)==expected[:count]
    return values

def emit_test_measurement(name,output,*,complete):
    if name==REPORT_MEASUREMENT_TEST:
        print('CI_RETAINED_REPORT_SIZE_V2 '+json.dumps(report_measurement(output),sort_keys=True))
    else:
        values=composition_measurement(name,output,complete=complete)
        print('CI_COMPOSITION_SIZE_V1 '+json.dumps(dict(test=name,complete=complete,test_passed=complete,records=values),sort_keys=True))

def intent_elapsed_ms(started):
    # Harness monotonic execution interval only; never a native authority clock.
    elapsed=time.monotonic()-started
    assert 0<=elapsed<=360
    return int(elapsed*1000)
def run_intent_validation_tests(root,env):
    assert INTENT_VALIDATION_TESTS and len(set(INTENT_VALIDATION_TESTS))==len(INTENT_VALIDATION_TESTS)
    selected=S.select_build_environment(env,'coordinator-observed',S.A.SEMANTIC_PROFILE)
    args=['rustup','run','1.99.0','cargo','test','--locked','--lib','--no-run','--no-default-features','--message-format=json','-p','wholepact-signer','--features','wholepact-signer/coordinated-financial-workflow-v1,wholepact-signer/synthetic-qualification']
    raw=S.checked(args,'compile',env=selected,seconds=900,limit=32*1024*1024)
    executable=intent_test_executable(raw,root/'target-shared')
    started=time.monotonic();deadline=started+360
    def fixed(args,measurement=None):
        remaining=deadline-time.monotonic();assert remaining>0
        try:
            raw=S.checked(args,'compile',env=selected,seconds=min(60,remaining),limit=1024*1024)
        except S.Failure as error:
            if measurement:
                try:
                    emit_test_measurement(measurement,error.output.decode('utf-8',errors='strict'),complete=False)
                except BaseException:
                    pass # Missing/malformed measurements never replace the original failure.
                finally:
                    error.output=b'' # Never expose measurement-test stdout through compiler tails.
            raise
        try:return raw.decode('utf-8',errors='strict')
        except UnicodeError:raise AssertionError('measurement_encoding' if measurement else 'test_encoding') from None
    # Verify the entire fixed selection before executing the first test.
    for name in INTENT_VALIDATION_TESTS:
        listing=fixed([str(executable),'--list','--exact',name])
        assert [line for line in listing.splitlines() if line.endswith(': test')]==[name+': test']
    for name in INTENT_VALIDATION_TESTS:
        test_started=time.monotonic()
        measurement=name if name==REPORT_MEASUREMENT_TEST or name in COMPOSITION_MEASUREMENT_TESTS else None
        output=fixed([str(executable),'--exact',name,'--test-threads=1']+(['--nocapture'] if measurement else []),measurement=measurement)
        assert 'test result: ok. 1 passed; 0 failed; 0 ignored;' in output
        if measurement:emit_test_measurement(measurement,output,complete=True)
        print('CI_INTENT_VALIDATION_TEST '+json.dumps(dict(name=name,passed=True,ignored=0,elapsed_ms=intent_elapsed_ms(test_started)),sort_keys=True))
    print('CI_INTENT_VALIDATION_TESTS '+json.dumps(dict(actual_maintained_tests=len(INTENT_VALIDATION_TESTS),elapsed_ms=intent_elapsed_ms(started),passed=True,genuine_pair_or_final_fixture=False,fullflow=False),sort_keys=True))
    return len(INTENT_VALIDATION_TESTS)
def preflight_failure_output(raw):
    """Pre-credential Cargo errors first; same combined 64 KiB text ceiling.

    The command already bounds capture to 32 MiB. Never use this projection for
    runtime output. Only Cargo error records contribute primary diagnostics;
    dependency warnings and malformed JSON cannot displace the first errors.
    """
    budget=S.BUILD_LOG_LIMIT//2
    primary=bytearray();errors=0;primary_total=0
    for line in raw.splitlines():
        if not line.startswith(b'{'):continue
        try:row=json.loads(line)
        except (ValueError,UnicodeError):continue
        if type(row) is not dict or row.get('reason')!='compiler-message':continue
        message=row.get('message')
        if type(message) is not dict or message.get('level')!='error':continue
        errors+=1
        rendered=message.get('rendered')
        if type(rendered) is not str:
            # Structured rustc spans remain useful if rendered text is absent.
            rendered=json.dumps({k:message[k] for k in ('message','code','spans') if k in message},ensure_ascii=True)
        encoded=(rendered+'\n').encode('utf-8');primary_total+=len(encoded)
        if len(primary)<budget:
            primary.extend(encoded[:budget-len(primary)])
    clean=S.build_failure_tail(bytes(primary))['combined_stdout_stderr_tail']
    clean=clean.encode('utf-8')[:budget].decode('utf-8',errors='ignore')
    remaining=S.BUILD_LOG_LIMIT-len(clean.encode('utf-8'))
    tail=S.build_failure_tail(raw[-remaining:])['combined_stdout_stderr_tail']
    tail=tail.encode('utf-8')[-remaining:].decode('utf-8',errors='ignore')
    return dict(primary_compiler_errors=clean,primary_error_records=errors,
        primary_diagnostic_bytes=len(clean.encode('utf-8')),primary_diagnostics_truncated=primary_total>budget,
        combined_stdout_stderr_tail=tail,tail_bytes=len(tail.encode('utf-8')),
        captured_output_bytes=len(raw),tail_truncated=len(raw)>remaining)

def main():
    root=pathlib.Path(os.environ['PREFLIGHT_ROOT']).resolve();assert root.is_dir()
    env=dict(PATH=os.environ['PATH'],HOME=str(root/'home'),CARGO_HOME=str(root/'cargo'),CARGO_TARGET_DIR=str(root/'target-shared'),CARGO_BUILD_JOBS='3',CARGO_INCREMENTAL='0',RUSTUP_HOME=os.environ['RUSTUP_HOME'],GIT_CONFIG_NOSYSTEM='1',GIT_CONFIG_GLOBAL='/dev/null',GIT_TERMINAL_PROMPT='0')
    sha=os.environ['SOURCE_COMMIT'];S.exact_source(sha)
    try:
        env=S.encrypted_build_environment(root,env)
        selected=S.select_build_environment(env,'coordinator-observed',S.A.SEMANTIC_PROFILE)
        coordinator_executed=run_coordinator_tests(root,env)
        args=['rustup','run','1.99.0','cargo','check','--locked','--tests','--no-default-features','--message-format=json']
        for package in PACKAGES:args+=['-p',package]
        args+=['--features',','.join(FEATURES)]
        raw=S.checked(args,'compile',env=selected,seconds=900,limit=32*1024*1024)
        validate(raw,root/'target-shared');executed=run_handoff_security_tests(root,env);intent_executed=run_intent_validation_tests(root,env);fixture_executed=run_fixture_lifetime_tests(root,env);absence=check_signer_absence(root,env);S.exact_source(sha)
        print('CI_CLOSE_PREFLIGHT_CONTEXTS '+json.dumps(dict(schema_version=2,actual_test_contexts=list(PACKAGES),actual_semantic_script_crates=list(SCRIPTS),typecheck_passed=True,coordinator_selected_tests_executed=coordinator_executed,repaint_schedule_tests_executed=len(REPAINT_TESTS),retirement_handoff_tests_executed=len(COORDINATOR_DIAGNOSTIC_TESTS),selector_export_tests_executed=len(SELECTOR_EXPORT_TESTS),admission_scroll_tests_executed=len(ADMISSION_SCROLL_TESTS),witness_first_failure_tests_executed=len(WITNESS_FIRST_FAILURE_TESTS),signing_retirement_ui_tests_executed=len(SIGNING_RETIREMENT_UI_TESTS),signer_observed_api_absent_profiles=absence,selected_maintained_tests_executed=executed,intent_validation_tests_executed=intent_executed,fixture_lifetime_maintained_tests_executed=fixture_executed,full_native_execution=False,fullflow=False),sort_keys=True))
    except S.Failure as error:
        # Pre-credential compiler text only; same bounded sanitizer as fresh build.
        try:
            print('CI_CLOSE_PREFLIGHT_FAILURE '+json.dumps(dict(stage=error.stage,check=error.check,**preflight_failure_output(error.output)),sort_keys=True))
        except BaseException:
            pass # Best-effort diagnostics never replace the original failure.
        raise
    finally:
        # This exact temporary prefix was created exclusively above; never a source path.
        shutil.rmtree(root/'sqlcipher',ignore_errors=True)
if __name__=='__main__':main()
