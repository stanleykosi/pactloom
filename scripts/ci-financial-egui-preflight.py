#!/usr/bin/env python3
"""D62 fixed real-egui experiment only; no fullflow or artifact reuse qualification."""
import importlib.util,json,os,pathlib,shutil,stat,sys,tempfile
HERE=pathlib.Path(__file__).resolve().parent
spec=importlib.util.spec_from_file_location('egui_preflight_contexts',HERE/'ci-close-preflight-contexts.py');P=importlib.util.module_from_spec(spec);spec.loader.exec_module(P)
S=P.S
spec=importlib.util.spec_from_file_location('egui_fixed_bridge',HERE/'ci-financial-egui-layout.py');B=importlib.util.module_from_spec(spec);spec.loader.exec_module(B)
EXPORT_TEST='consent_journal::authority::durable_delivery_admission_intent_v3::coordinated_v1::full_intent_validation_tests::retained_report_tests::export_actual_material_admit_layout_dto'
LAYOUT_TEST='financial_source_ui::egui_layout_tests::actual_admit_review_layout_protocol'
DTO_ENV='WHOLEPACT_CI_EGUI_ADMIT_FIXTURE'
def coordinator_test_executable(raw,target):
    rows=[json.loads(line) for line in raw.splitlines() if line.startswith(b'{')]
    packages={};executables=[]
    for row in rows:
        if row.get('reason')!='compiler-artifact':continue
        t=row.get('target',{});manifest=row.get('manifest_path','')
        if t.get('kind')==['custom-build'] and pathlib.Path(manifest).is_relative_to(S.REPO):
            crate=pathlib.Path(manifest).parent.name
            assert crate in P.SCRIPTS and crate not in packages.values()
            assert t.get('name')=='build-script-build' and t.get('src_path')==str(S.REPO/'crates'/crate/'build.rs')
            packages[row['package_id']]=crate
        if manifest!=str(S.REPO/'crates/wholepact-financial-coordinator/Cargo.toml') or row.get('executable') is None:continue
        assert row.get('profile',{}).get('test') is True
        assert t.get('kind')==['bin'] and t.get('name')=='wholepact-financial-coordinator'
        assert t.get('src_path')==str(S.REPO/'crates/wholepact-financial-coordinator/src/main.rs')
        assert sorted(row.get('features',[]))==sorted(S.A.RECIPE['artifact_features']['coordinator-observed'])
        exe=pathlib.Path(row['executable'])
        assert exe.is_file() and not exe.is_symlink() and exe.resolve().is_relative_to(target.resolve()) and os.access(exe,os.X_OK)
        assert str(exe) in row.get('filenames',[]);executables.append(exe)
    assert len(executables)==1 and set(packages.values())==set(P.SCRIPTS)
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
def fixed_listing(executable,name,env,*,ignored=False):
    raw=S.checked([str(executable),'--list','--exact',name]+(['--ignored'] if ignored else []),'compile',env=env,seconds=10,limit=16384)
    listing=raw.decode('utf-8',errors='strict')
    assert [line for line in listing.splitlines() if line.endswith(': test')]==[name+': test']
def export_measurement(raw):
    marker='EGUI_ADMIT_FIXTURE_V1 ';values=[]
    for line in raw.decode('utf-8',errors='strict').splitlines():
        if marker not in line:continue
        prefix,data=line.split(marker,1)
        assert prefix in ('','test '+EXPORT_TEST+' ... ') and len(data)<=512
        def pairs(items):
            result={}
            for key,value in items:
                assert key not in result;result[key]=value
            return result
        value=json.loads(data,object_pairs_hook=pairs)
        assert type(value) is dict and set(value)=={'bytes','material_input_id_bytes','public_dto_valid'}
        assert type(value['bytes']) is int and 0<value['bytes']<=60*1024
        assert type(value['material_input_id_bytes']) is int and 75<=value['material_input_id_bytes']<=60*1024
        assert value['public_dto_valid'] is True;values.append(value)
    assert len(values)==1
    return values[0]
def layout_summary(raw):
    # No raw child output reaches the console, even for malformed/failing tests.
    assert type(raw) is bytes and len(raw)<=16384
    def pairs(items):
        result={}
        for key,value in items:
            assert key not in result;result[key]=value
        return result
    try:return B.validate_summary(json.loads(raw.decode('utf-8',errors='strict'),object_pairs_hook=pairs))
    except (ValueError,UnicodeError,B.DiagnosticError):raise AssertionError('invalid finite layout summary') from None
def private_dto(path):
    info=path.lstat()
    assert stat.S_ISREG(info.st_mode) and stat.S_IMODE(info.st_mode)==0o600 and info.st_uid==os.getuid() and 0<info.st_size<=60*1024
    return info.st_dev,info.st_ino

def main():
    root=pathlib.Path(os.environ['PREFLIGHT_ROOT']).resolve();assert root.is_dir()
    env=dict(PATH=os.environ['PATH'],HOME=str(root/'home'),CARGO_HOME=str(root/'cargo'),CARGO_TARGET_DIR=str(root/'target-shared'),CARGO_BUILD_JOBS='3',CARGO_INCREMENTAL='0',RUSTUP_HOME=os.environ['RUSTUP_HOME'],GIT_CONFIG_NOSYSTEM='1',GIT_CONFIG_GLOBAL='/dev/null',GIT_TERMINAL_PROMPT='0')
    sha=os.environ['SOURCE_COMMIT'];S.exact_source(sha);private=None;phase='compile'
    try:
        env=S.encrypted_build_environment(root,env)
        selected=S.select_build_environment(env,'coordinator-observed',S.A.SEMANTIC_PROFILE)
        raw=S.checked(['rustup','run','1.99.0','cargo','test','--locked','--lib','--no-run','--no-default-features','--message-format=json','-p','wholepact-signer','--features','wholepact-signer/coordinated-financial-workflow-v1,wholepact-signer/synthetic-qualification'],'compile',env=selected,seconds=900,limit=32*1024*1024)
        exporter=P.intent_test_executable(raw,root/'target-shared')
        raw=S.checked(['rustup','run','1.99.0','cargo','test','--locked','--bin','wholepact-financial-coordinator','--no-run','--no-default-features','--message-format=json','-p','wholepact-financial-coordinator','--features','coordinated-financial-runtime'],'compile',env=selected,seconds=900,limit=32*1024*1024)
        coordinator=coordinator_test_executable(raw,root/'target-shared')
        assert EXPORT_TEST!='PENDING_FROZEN_EXPORT_TEST'
        fixed_listing(exporter,EXPORT_TEST,selected,ignored=True);fixed_listing(coordinator,LAYOUT_TEST,selected,ignored=True)
        S.exact_source(sha)
        print('CI_EGUI_LAYOUT_BUILD '+json.dumps(dict(schema=1,exact_test_binaries=2,coordinator_cfg_consumers=4,signer_cfg_consumers=2,full_product_build=False),sort_keys=True),flush=True)
        phase='export';private=pathlib.Path(tempfile.mkdtemp(prefix='egui-private-',dir=root));private.chmod(0o700)
        dto=private/'admit.json';report=private/'finite-report.json';runenv=dict(selected,**{DTO_ENV:str(dto)})
        try:output=S.checked([str(exporter),'--exact',EXPORT_TEST,'--ignored','--nocapture','--test-threads=1'],'compile',env=runenv,seconds=60,limit=1024*1024)
        except S.Failure as error:error.output=b'';raise
        assert b'test result: ok. 1 passed; 0 failed; 0 ignored;' in output
        identity=private_dto(dto);measurement=export_measurement(output);output=b''
        assert measurement['bytes']==dto.stat().st_size
        print('CI_EGUI_LAYOUT_EXPORT '+json.dumps(dict(schema=1,exact_test=EXPORT_TEST,passed=True,ignored=0,private_mode_verified=True,measurement=measurement),sort_keys=True),flush=True)
        phase='layout'
        status,output=S.command([sys.executable,'-I','-B',str(HERE/'ci-financial-egui-layout.py'),'--coordinator-test-binary',str(coordinator),'--output',str(report)],'compile',env=runenv,seconds=180,limit=65536)
        value=layout_summary(output);output=b''
        print('CI_EGUI_LAYOUT_RESULT '+json.dumps(value,sort_keys=True),flush=True)
        assert not dto.exists(),'private DTO must be removed by bridge'
        assert status==0 and value['outcome']=='source_bound_arm_reachable','actual layout did not reach native enabled arm'
        S.exact_source(sha)
    except S.Failure as error:
        if phase=='compile':
            try:print('CI_EGUI_PREFLIGHT_FAILURE '+json.dumps(dict(stage=error.stage,check=error.check,**P.preflight_failure_output(error.output)),sort_keys=True))
            except BaseException:pass
        else:
            error.output=b''
            print('CI_EGUI_PREFLIGHT_FAILURE '+json.dumps(dict(stage=phase,check='selected_test_failed',raw_output_suppressed=True)))
        raise
    finally:
        primary=sys.exc_info()[0] is not None;cleanup_failed=False
        for owned in (private,root/'sqlcipher'):
            if owned is None:continue
            try:
                if owned.exists():shutil.rmtree(owned)
            except OSError:cleanup_failed=True
        if cleanup_failed:
            print('CI_EGUI_PREFLIGHT_CLEANUP '+json.dumps(dict(verified=False,primary_failure_preserved=primary)))
            if not primary:raise AssertionError('diagnostic cleanup failed')
if __name__=='__main__':main()
