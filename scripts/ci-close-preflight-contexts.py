#!/usr/bin/env python3
"""Fixed pre-credential P45 typecheck; no fixture, native runtime or artifact export."""
import importlib.util,json,os,pathlib,shutil
HERE=pathlib.Path(__file__).resolve().parent
spec=importlib.util.spec_from_file_location('preflight_supervisor',HERE/'ci-financial-supervisor.py');S=importlib.util.module_from_spec(spec);spec.loader.exec_module(S)
PACKAGES=('wholepact-native-host','wholepact-authority','wholepact-financial-coordinator-origin','wholepact-signer')
SCRIPTS=('wholepact-native-host','wholepact-financial-coordinator-origin','wholepact-signer')
FEATURES=('wholepact-native-host/coordinated-financial-workflow-v1','wholepact-signer/coordinated-financial-workflow-v1',*(f'wholepact-authority/{x}' for x in ('coordinated-witness-financial-history','coordinated-witness-financial-continuation','coordinated-witness-financial-signing','coordinated-witness-completed-pair')))
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
            if t.get('kind')==['lib'] and t.get('name')==crate.replace('-','_') and t.get('src_path')==str(S.REPO/'crates'/crate/'src/lib.rs'):
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
def main():
    root=pathlib.Path(os.environ['PREFLIGHT_ROOT']).resolve();assert root.is_dir()
    env=dict(PATH=os.environ['PATH'],HOME=str(root/'home'),CARGO_HOME=str(root/'cargo'),CARGO_TARGET_DIR=str(root/'target-shared'),CARGO_BUILD_JOBS='3',CARGO_INCREMENTAL='0',RUSTUP_HOME=os.environ['RUSTUP_HOME'],GIT_CONFIG_NOSYSTEM='1',GIT_CONFIG_GLOBAL='/dev/null',GIT_TERMINAL_PROMPT='0')
    sha=os.environ['SOURCE_COMMIT'];S.exact_source(sha)
    try:
        env=S.encrypted_build_environment(root,env)
        selected=S.select_build_environment(env,'coordinator-observed',S.A.SEMANTIC_PROFILE)
        args=['rustup','run','1.99.0','cargo','check','--locked','--lib','--tests','--no-default-features','--message-format=json']
        for package in PACKAGES:args+=['-p',package]
        args+=['--features',','.join(FEATURES)]
        raw=S.checked(args,'compile',env=selected,seconds=900,limit=32*1024*1024)
        validate(raw,root/'target-shared');S.exact_source(sha)
        print('CI_CLOSE_PREFLIGHT_CONTEXTS '+json.dumps(dict(schema_version=1,actual_test_contexts=list(PACKAGES),actual_semantic_script_crates=list(SCRIPTS),typecheck_passed=True,native_execution=False,fullflow=False),sort_keys=True))
    except S.Failure as error:
        # Pre-credential compiler text only; same bounded sanitizer as fresh build.
        print('CI_CLOSE_PREFLIGHT_FAILURE '+json.dumps(dict(stage=error.stage,check=error.check,**S.build_failure_tail(error.output)),sort_keys=True))
        raise
    finally:
        # This exact temporary prefix was created exclusively above; never a source path.
        shutil.rmtree(root/'sqlcipher',ignore_errors=True)
if __name__=='__main__':main()
