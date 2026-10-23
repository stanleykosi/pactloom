"""Fixed preserved-P35 preparation diagnostic, separate from financial full flow.

No generic command or test selector. No imports of unverified P/H bytes, no
native compilation, raw output publication, or full-flow success projection.
"""
import contextlib
import hashlib
import json
import os
import pathlib
import shutil
import re
import stat
import subprocess
import platform
import signal
import sys
import tempfile
import types
import unittest

HERE=pathlib.Path(__file__).resolve().parent
POLICY='p35-preserved-durable-delivery-admission-diagnostic-v1'
WRAPPER_SHA='16531ec93aa8b9b978f2c92a6b5a7d48e27259e30cb7bb39e5a58edac6f0b1c7'
PHASE='durable-delivery-admission'
TEST='host::manual_enrollment::command::roster_publication_v2::sequential_construction_v3::qualification::durable_proposal_v1::delivery_admission_v2::durable_delivery_native_v3_admission_reopens_original_after_process_death'
ENTRYPOINT=['/usr/local/bin/python3','-I','-B','/opt/ci-financial/ci-synthetic-output.py','/opt/ci-financial/pristine-setup',PHASE]
STAGES=frozenset(('bootstrap','source','tests','artifact','image','container','wrapper','cleanup','complete'))

class Rejected(Exception):pass

def need(ok):
    if not ok:raise Rejected('diagnostic_verification')

def load_verified(path,expected=None,name='diagnostic_source'):
    data=path.read_bytes();need(expected is None or hashlib.sha256(data).hexdigest()==expected)
    module=types.ModuleType(name);module.__file__=str(path);sys.modules[name]=module
    exec(compile(data,str(path),'exec'),module.__dict__);return module

class Records:
    """Revalidate wrapper output; only schema4 re-encoding may be published."""
    def __init__(self,wrapper):self.W=wrapper;self.row=None;self.result=None;self.cleanup_unverified=False;self.cores=0;self.failures=0;self.invalid=False
    def __call__(self,line):
        try:return self.accept(line)
        except BaseException:
            self.invalid=True;self.row=None;raise
    def accept(self,line):
        need(type(line) is bytes and 0<len(line)<=8192 and self.result is None)
        if line.startswith(b'CI_SYNTHETIC_DURABLE_DELIVERY '):
            need(self.row is None);text=line[len(b'CI_SYNTHETIC_DURABLE_DELIVERY '):].decode('utf8')
            self.row=self.W.public_durable_delivery(text);return
        if line==b'CI_SYNTHETIC_RESULT phase=durable-delivery-admission passed=true cleanup_verified=true':self.result=True;return
        if line==b'CI_SYNTHETIC_RESULT passed=false details_withheld=true':self.result=False;return
        if line==b'CI_SYNTHETIC_RESULT cleanup_unverified=true outcome_unverified=true':
            need(not self.cleanup_unverified);self.cleanup_unverified=True;return
        projected=self.W.public_line(line,TEST)
        need(projected is not None and projected[0] in ('core','failure'))
        if projected[0]=='core':self.cores+=1;need(self.cores==1)
        else:self.failures+=1;need(self.failures==1)
    def finish(self,status):
        need(type(status) is int and self.result is not None and not self.invalid)
        if self.result:
            need(status==0 and self.cores==1 and self.failures==0 and self.row is not None and self.row['result']=='passed' and not self.cleanup_unverified)
        else:need(status!=0)
        return self.result


def inspect_container(S,name,token,image_id,source):
    rows=S.loads(S.docker(['inspect','--type','container',name],'container',limit=65536))
    need(type(rows) is list and len(rows)==1 and type(rows[0]) is dict)
    r=rows[0];c=r.get('Config');h=r.get('HostConfig');need(type(c) is dict and type(h) is dict)
    need(type(c.get('Labels')) is dict and c['Labels'].get(S.LABEL)==token and c['Labels'].get(S.SOURCE_LABEL)==source)
    need(r.get('Image')==image_id and c.get('Image')==image_id)
    need(c.get('User')=='10001:10001' and c.get('Entrypoint')==ENTRYPOINT and c.get('Cmd') in (None,[]) and c.get('WorkingDir')=='/opt/ci-financial')
    need(h.get('NetworkMode')=='none' and h.get('ReadonlyRootfs') is True and h.get('Privileged') is False)
    need(h.get('CapDrop')==['ALL'] and h.get('CapAdd') in (None,[]) and h.get('SecurityOpt')==['no-new-privileges:true'])
    need(h.get('PidMode')=='' and h.get('IpcMode')=='private' and h.get('UsernsMode')=='' and h.get('CgroupnsMode')=='private')
    need(S.B.absent(h.get('GroupAdd')) and h.get('LogConfig')=={'Type':'none','Config':{}} and h.get('RestartPolicy')=={'Name':'no','MaximumRetryCount':0} and h.get('AutoRemove') is False)
    for field,value in (('PidsLimit',128),('Memory',2*1024**3),('MemorySwap',2*1024**3),('NanoCpus',2_000_000_000)):
        need(type(h.get(field)) is int and h[field]==value)
    for field in ('Binds','Devices','DeviceRequests','Mounts'):need(S.B.absent(h.get(field)))
    need(S.B.absent(c.get('Volumes')) or c.get('Volumes')=={})
    mounts=r.get('Mounts');need(type(mounts) is list and all(type(m) is dict and m.get('Type')=='tmpfs' and m.get('Destination') in S.TMPFS and not m.get('Source') for m in mounts))
    need(type(h.get('Tmpfs')) is dict and set(h['Tmpfs'])==set(S.TMPFS))
    for path,expected in S.TMPFS.items():
        value=h['Tmpfs'][path];need(type(value) is str);parts=value.split(',');need(len(parts)==len(set(parts)) and set(parts)==set(expected.split(',')))
    limits=h.get('Ulimits');expected=[{'Name':'core','Hard':0,'Soft':0},{'Name':'nofile','Hard':512,'Soft':512}]
    need(type(limits) is list and len(limits)==2 and limits[0]!=limits[1] and all(x in expected for x in limits))
    env=c.get('Env');need(type(env) is list and all(type(x) is str for x in env))
    parsed={x.split('=',1)[0]:x.split('=',1)[1] for x in env if '=' in x};need(len(parsed)==len(env))
    need(parsed.get('CARGO_TARGET_DIR')=='/opt/ci-financial' and parsed.get('TMPDIR')=='/tmp')
    need(not any(any(word in k.upper() for word in ('TOKEN','PASSWORD','SECRET','CREDENTIAL')) or k=='GITHUB_STEP_SUMMARY' for k in parsed))


def run_container(S,image_id,token,source,records):
    name='wp-financial-'+token+'-external'
    need(not S.names(token))
    args=['create','--pull','never','--name',name,'--label',S.LABEL+'='+token,'--label',S.SOURCE_LABEL+'='+source,
        '--network','none','--read-only','--cap-drop','ALL','--security-opt','no-new-privileges:true',
        '--pids-limit','128','--memory','2g','--memory-swap','2g','--cpus','2','--ipc','private','--cgroupns','private',
        '--ulimit','core=0:0','--ulimit','nofile=512:512','--log-driver','none','--restart','no']
    for path,options in S.TMPFS.items():args+=['--tmpfs',path+':'+options]
    S.docker(args+[image_id],'container',limit=4096)
    inspect_container(S,name,token,image_id,source)
    # Native900s and wrapper1080s unchanged. Bound includes list30s/parent cleanup.
    status,raw=S.command(['docker','start','--attach',name],'runtime',seconds=1140,limit=65536,env=S.docker_env(),on_line=records)
    need(raw.endswith(b'\n'));return records.finish(status)


def trusted_cleanup(L,trusted):
    # Run original current-P35 cleanup implementation; suppress its full-flow
    # cleanup-only result. Container teardown never upgrades native cleanup.
    with open(os.devnull,'w') as sink,contextlib.redirect_stdout(sink):
        return L.trusted_cleanup(trusted)


def emit_result(stage,passed,clean,records):
    if records is not None and records.row is not None:
        print('CI_SYNTHETIC_DURABLE_DELIVERY '+json.dumps(records.row,sort_keys=True,separators=(',',':')),flush=True)
    value=dict(version=1,policy=POLICY,stage=stage if stage in STAGES else 'bootstrap',diagnostic_passed=bool(passed and clean),
        native_wrapper_cleanup_verified=bool(passed and records and records.result is True and not records.cleanup_unverified),
        wrapper_cleanup_unverified=bool(not passed or records is None or records.result is not True or records.cleanup_unverified),
        container_image_cache_cleanup_verified=bool(clean),native_binaries_rebuilt=False,full_flow_verified=False,
        coordinated_pair_verified=False,public_chain_verified=False,dispatch_requested=False,deployment_verified=False)
    print('CI_PREPARATION_DIAGNOSTIC_RESULT '+json.dumps(value,sort_keys=True,separators=(',',':')),flush=True)


def bootstrap(launcher):
    checks={'GITHUB_ACTIONS':'true','RUNNER_OS':'Linux','RUNNER_ENVIRONMENT':'github-hosted','GITHUB_REPOSITORY':'stanleykosi/pactloom','GITHUB_REF':'refs/heads/qualification/durable-proposal-v1','GITHUB_EVENT_NAME':'push','GITHUB_JOB':'synthetic-only'}
    need(all(os.environ.get(k)==v for k,v in checks.items()) and platform.machine()=='x86_64')
    sha=os.environ.get('GITHUB_SHA','');need(re.fullmatch('[0-9a-f]{40}',sha) is not None)
    root=pathlib.Path(launcher).resolve();need(HERE.parents[1]==root)
    env=dict(PATH=os.environ['PATH'],HOME='/nonexistent',GIT_CONFIG_NOSYSTEM='1',GIT_CONFIG_GLOBAL='/dev/null',GIT_TERMINAL_PROMPT='0')
    def git(*args):return subprocess.check_output(['git','-C',str(root),*args],env=env,stderr=subprocess.DEVNULL)
    need(git('rev-parse','HEAD').strip().decode()==sha)
    def read(path):
        need(path.absolute()==path.resolve() and not path.is_symlink());name=str(path.relative_to(root))
        row=git('ls-tree','-z',sha,'--',name);need(row.endswith(b'\0') and row.count(b'\0')==1)
        fields,actual=row[:-1].split(b'\t');mode,kind,oid=fields.split();need(actual.decode()==name and mode in (b'100644',b'100755') and kind==b'blob')
        data=git('cat-file','blob',oid.decode());meta=path.lstat();need(stat.S_ISREG(meta.st_mode) and meta.st_nlink==1 and stat.S_IMODE(meta.st_mode)==int(mode,8)&0o777 and path.read_bytes()==data)
        return data
    read(pathlib.Path(__file__));lp=HERE/'launch_adapter.py';raw=read(lp)
    L=types.ModuleType('diagnostic_launcher');L.__file__=str(lp);sys.modules[L.__name__]=L;exec(compile(raw,str(lp),'exec'),L.__dict__)
    trusted,_=L.bootstrap(root);trusted.tracked(pathlib.Path(__file__));return L,trusted


# Reviewed scope: historical route assertions and disjoint Pristine/financial
# source projections. All 163 other existing wrapper tests remain mandatory.
WRAPPER_EXCLUSIONS=frozenset(['PublicOutputTests.test_durable_fail_fast_order_preserves_final_regression_gates', 'DurableEndpointGateTests.test_endpoint_gate_follows_signer_validation_and_preserves_final_cleanup', 'PrivateWorkspaceOutputTests.test_private_workspace_exact_phase_and_unexpanded_clock_bounds', 'PublicOutputTests.test_completion_claim_and_channel_clock_are_closed_diagnostics', 'PublicOutputTests.test_durable_acquire_reply_loss_reuses_only_same_compiled_binary_in_separate_gate', 'PublicOutputTests.test_durable_fixed_signing_is_exact_ignored_and_preserves_bounds', 'PublicOutputTests.test_durable_runner_separates_old_owner_baseline_from_new_process_restart', 'PublicOutputTests.test_failure_enum_sets_match_compiled_source', 'PublicOutputTests.test_harness_failure_reasons_match_exact_rust_enum', 'PublicOutputTests.test_native_lease_origin_diagnostics_expose_only_closed_kinds', 'PublicOutputTests.test_rolling_preflight_preserves_ten_original_plus_twelve_optional_cases', 'PublicOutputTests.test_witness_diagnostics_use_exact_closed_authority_projection'])
def wrapper_preflight(path):
    module=load_verified(path,name='diagnostic_wrapper_tests')
    suite=unittest.defaultTestLoader.loadTestsFromModule(module)
    def flatten(item):
        for test in item:
            if isinstance(test,unittest.TestSuite):yield from flatten(test)
            else:yield test
    tests=list(flatten(suite));need(len(tests)==175)
    key=lambda test:'.'.join(test.id().split('.')[-2:])
    need({key(test) for test in tests}&WRAPPER_EXCLUSIONS==WRAPPER_EXCLUSIONS)
    selected=unittest.TestSuite(test for test in tests if key(test) not in WRAPPER_EXCLUSIONS)
    with open(os.devnull,'w') as sink,contextlib.redirect_stdout(sink),contextlib.redirect_stderr(sink):
        result=unittest.TextTestRunner(stream=sink).run(selected)
    need(result.testsRun==163 and result.wasSuccessful())


IMAGE_OPERATIONS=frozenset(('context','context_inputs','context_manifest','context_download','context_write','source_recheck','base_pull','image_build','image_descriptor'))


def image_failure_record(S,operation,error):
    # Only closed metadata from the pre-native image stage; never exception text,
    # raw tool tails, commands, paths, URLs or package contents.
    code=getattr(error,'code',None)
    if type(code) is not str or code not in S.PACKAGE_CHECKS|S.CHECKS|S.IMAGE_CHECKS:code='unavailable'
    status=getattr(error,'exit_status',None)
    if type(status) is not int or not -255<=status<=255:status=None
    cleanup=getattr(error,'cleanup_failed',None)
    if type(cleanup) is not bool:cleanup=None
    raw=getattr(error,'output',None);found=[]
    if operation=='image_build' and type(raw) is bytes and len(raw)<=8*1024*1024:
        for line in raw.splitlines():
            if len(line)>4096:continue
            start=line.find(b'{')
            if start<0:continue
            try:value=S.loads(line[start:])
            except Exception:continue
            if (type(value) is dict and set(value)=={'schema_version','phase','code','cleanup_failed'}
                and type(value['schema_version']) is int and value['schema_version']==1
                and type(value['phase']) is str and value['phase'] in S.IMAGE_PHASES
                and type(value['code']) is str and value['code'] in S.IMAGE_CHECKS
                and type(value['cleanup_failed']) is bool and value not in found):found.append(value)
    installer=found[0] if len(found)==1 else None
    return dict(version=1,policy=POLICY,operation=operation if operation in IMAGE_OPERATIONS else 'unavailable',
        code=code,exit_status=status,operation_cleanup_failed=cleanup,
        installer_record_available=installer is not None,installer=installer,native_started=False)

class ImageProgress:
    def __init__(self,S):self.S=S;self.operation='context'
    def advance(self,operation):
        need(operation in IMAGE_OPERATIONS);self.operation=operation
    def perform(self,operation,action):
        self.advance(operation)
        try:return action()
        except BaseException as error:
            try:print('CI_PREPARATION_IMAGE_FAILURE '+json.dumps(image_failure_record(self.S,self.operation,error),sort_keys=True,separators=(',',':')),flush=True)
            except BaseException:pass
            raise


def main():
    os.umask(0o077);stage='bootstrap';clean=False;passed=False;records=None;root=None;trusted=None;L=None;cleanup_only=False
    try:
        if len(sys.argv)==3 and sys.argv[1]=='cleanup':
            cleanup_only=True;L,trusted=bootstrap(sys.argv[2]);stage='cleanup'
            clean=trusted_cleanup(L,trusted)
            # No diagnostic/native result is inferred from cleanup-only mode.
            return 0 if clean else 1
        need(len(sys.argv)==7 and sys.argv[1]=='run')
        _,_,plan_path,producer,harness,staging,launcher=sys.argv
        L,trusted=bootstrap(launcher);L.load_helpers(trusted)
        builder=trusted.module('diagnostic_image',HERE/'preparation_image.py')
        plan=L.validate_plan(json.loads(trusted.tracked(pathlib.Path(plan_path)),object_pairs_hook=L.V.A.pairs))
        need(plan['harness']=={k:L.V.PRODUCER[k] for k in ('repository','source','source_tree')} and plan['reviewed_runtime_changes']=={})
        stage='source';p_inv,h_inv,identity=L.verify_sources(plan,producer,harness,launcher)
        os.chdir(harness);S=L.load_supervisor(harness);event,token=S.context();need(event==identity['source'])
        W=load_verified(pathlib.Path(harness)/'scripts/ci-synthetic-output.py',WRAPPER_SHA,'diagnostic_wrapper')
        need(W.TESTS[PHASE]==(TEST,1080));records=Records(W)
        def interrupted(_signal,_frame):raise Rejected('interrupted')
        signal.signal(signal.SIGTERM,interrupted);signal.signal(signal.SIGINT,interrupted)
        root=pathlib.Path(tempfile.mkdtemp(prefix='wholepact-financial-',dir=os.environ['RUNNER_TEMP']));(root/'docker').mkdir();os.environ['FINANCIAL_DOCKER_CONFIG']=str(root/'docker')
        stage='tests'
        S.checked([sys.executable,'-I','-B',str(HERE/'diagnostic_adapter.py'),'--wrapper-preflight'],'preflight',seconds=300,limit=1024*1024,env=L.safe_environment())
        S.exact_source(plan['harness']['source']);stage='artifact'
        inputs,evidence=L.acquire_verified_inputs(root,pathlib.Path(staging).resolve(),plan,p_inv,h_inv)
        need(evidence['permitted_runtime_changes']==[] and evidence['permitted_diagnostic_changes']==[])
        stage='image';context=root/'diagnostic-context';image_progress=ImageProgress(S)
        image_progress.perform('context',lambda:builder.build_context(context,pathlib.Path(producer).resolve(),plan['producer']['source'],inputs/'pristine-setup',progress=image_progress.advance))
        image_progress.perform('source_recheck',lambda:S.exact_source(plan['harness']['source']));image_progress.perform('base_pull',lambda:S.docker(['pull','--platform','linux/amd64',S.BASE],'image',seconds=300,limit=4*1024*1024))
        tag='wholepact-financial:'+token
        image_progress.perform('image_build',lambda:S.docker(['build','--network','none','--no-cache','--force-rm','--progress','plain','--target','runtime','--label',S.LABEL+'='+token,'--label',S.SOURCE_LABEL+'='+plan['producer']['source'],'--tag',tag,str(context)],'image',seconds=900,limit=8*1024*1024))
        image_id=image_progress.perform('image_descriptor',lambda:S.image_descriptor(tag,token,plan['producer']['source']))['id']
        stage='container';passed=run_container(S,image_id,token,plan['producer']['source'],records);stage='complete' if passed else 'wrapper'
    except BaseException:
        passed=False
    finally:
        if trusted is not None and not cleanup_only:
            try:clean=trusted_cleanup(L,trusted)
            except BaseException:clean=False
        if root is not None:
            try:shutil.rmtree(root)
            except OSError:clean=False
        if cleanup_only:
            print('CI_PREPARATION_DIAGNOSTIC_CLEANUP '+json.dumps(dict(version=1,policy=POLICY,container_image_cache_cleanup_verified=bool(clean)),sort_keys=True,separators=(',',':')),flush=True)
        else:emit_result(stage,passed,clean,records)
    return 0 if passed and clean else 1

if __name__=='__main__':
    if sys.argv[1:]==['--wrapper-preflight']:
        wrapper_preflight(pathlib.Path.cwd()/'scripts/ci-synthetic-output-tests.py')
    else:sys.exit(main())
