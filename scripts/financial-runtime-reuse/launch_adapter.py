"""PRIVATE review candidate, no network or activation at import.

Only P07 native producer is accepted. H contains runtime-only edits; L is
an independent exact CI event checkout. Missing future artifact/H pins reject.
No compiler invocation, context override, monkey-patch or runtime policy change.
"""
import hashlib
import types
import subprocess
import stat
import re
import platform
import json
import os
import pathlib
import shutil
import signal
import sys
import tarfile
import tempfile
import zipfile

HERE=pathlib.Path(__file__).resolve().parent
# Bootstrap is stdlib-only. No helper import or bytecode is executed until its
# tracked Git blob, working content and mode are verified against actual L.
V=None
CLEANUP_PINS={'cleanup_snapshot/scripts/ci-bootstrap-output.py': 'ce7c9a11b439e2a31f6e38c8401ab644840abba78c05482224484e5c931cc898', 'cleanup_snapshot/scripts/ci-bootstrap-supervisor.py': 'f606f43e4c3436209a380377ae7d8225fe8ee45828a748c776699f6190c709c0', 'cleanup_snapshot/scripts/ci-financial-artifacts.py': 'd24433f973c77d34e6d1f5c299cc1c7d00a7d024584bbfcb3d45e077c0e92f5d', 'cleanup_snapshot/scripts/ci-financial-contract.py': '574ad44f5f6414ce93b8c9f4b2c0954385dc7313f304aa28e961858f220fbc05', 'cleanup_snapshot/scripts/ci-financial-external-output.py': '10a067d58042bc86a21e8b640b129778036ca5b5b4383e9c5a109c303830a9a0', 'cleanup_snapshot/scripts/ci-financial-image.py': 'bd576c467c59a4958d77620c930076e9adb1551f8b8600d04de0f618a8a72b5b', 'cleanup_snapshot/scripts/ci-financial-ocr-image.py': '5dd479e0def902357714b07d1116a83f2c9ad215ea462493032502e29d564d67', 'cleanup_snapshot/scripts/ci-financial-supervisor.py': 'c9dc7952eca234465cce4d9efec730d7d422525b00af0c047cd25d549efdd94e', 'cleanup_snapshot/scripts/ci-ui-image.py': '181ebc76e3d15d02381ac6a7338346ea333c9026630968098dc3d25ee58b551b'}
HELPERS=('launch_adapter.py','verify_option.py','producer_artifacts.py','acquire_archive.py')
CI_KEYS=('PATH','RUNNER_TEMP','GITHUB_ACTIONS','RUNNER_OS','RUNNER_ENVIRONMENT',
    'GITHUB_REPOSITORY','GITHUB_REF','GITHUB_EVENT_NAME','GITHUB_SHA','GITHUB_RUN_ID',
    'GITHUB_RUN_ATTEMPT','GITHUB_JOB')

class BootstrapRejected(Exception):pass

def boot_require(ok,code):
    if not ok:raise BootstrapRejected(code)

def git_env():
    return dict(PATH=os.environ['PATH'],HOME='/nonexistent',GIT_CONFIG_NOSYSTEM='1',
        GIT_CONFIG_GLOBAL='/dev/null',GIT_TERMINAL_PROMPT='0')

def git_at(root,*args):
    return subprocess.check_output(['git','-C',str(root),*args],env=git_env(),stderr=subprocess.DEVNULL)

def event_identity():
    checks={'GITHUB_ACTIONS':'true','RUNNER_OS':'Linux','RUNNER_ENVIRONMENT':'github-hosted',
        'GITHUB_REPOSITORY':'stanleykosi/pactloom','GITHUB_REF':'refs/heads/qualification/durable-proposal-v1',
        'GITHUB_EVENT_NAME':'push','GITHUB_JOB':'synthetic-only'}
    boot_require(all(os.environ.get(k)==v for k,v in checks.items()) and platform.machine()=='x86_64','ci_context')
    sha=os.environ.get('GITHUB_SHA','');run=os.environ.get('GITHUB_RUN_ID','');attempt=os.environ.get('GITHUB_RUN_ATTEMPT','')
    boot_require(re.fullmatch('[0-9a-f]{40}',sha) is not None and re.fullmatch('[1-9][0-9]{0,19}',run) is not None
        and re.fullmatch('[1-9][0-9]{0,5}',attempt) is not None,'ci_identity')
    return sha,run+'-'+attempt+'-'+sha

class ReviewedLauncher:
    def __init__(self,root):
        self.root=pathlib.Path(root).resolve();self.sha,self.token=event_identity()
        boot_require(git_at(self.root,'rev-parse','HEAD').strip().decode()==self.sha,'launcher_commit')
        self.tree=git_at(self.root,'rev-parse','HEAD^{tree}').strip().decode()
        # Dirty/ignored unrelated working files cannot change loaded code: every
        # used path is checked against its tracked blob below. Native/H source
        # inventory retains its separate full-clean check for normal runs.
        self.cache={}
    def tracked(self,path):
        original=pathlib.Path(path);resolved=original.resolve()
        boot_require(resolved.is_relative_to(self.root) and original.absolute()==resolved
            and not original.is_symlink(),'tracked_location')
        relative=str(resolved.relative_to(self.root))
        boot_require(all(part not in ('','..','.') for part in relative.split('/')),'tracked_path')
        row=git_at(self.root,'ls-tree','-z',self.sha,'--',relative)
        boot_require(row.endswith(b'\0') and row.count(b'\0')==1,'untracked_launcher_input')
        fields,actual=row[:-1].split(b'\t');mode,kind,oid=fields.split(b' ')
        boot_require(actual.decode()==relative and kind==b'blob' and mode in (b'100644',b'100755'),'launcher_kind')
        data=git_at(self.root,'cat-file','blob',oid.decode())
        meta=original.lstat()
        boot_require(stat.S_ISREG(meta.st_mode) and meta.st_nlink==1
            and stat.S_IMODE(meta.st_mode)==(int(mode,8)&0o777)
            and original.read_bytes()==data,'launcher_working_mismatch')
        return data
    def module(self,name,path,**injected):
        data=self.tracked(path)
        module=types.ModuleType(name);module.__file__=str(path);module.__dict__.update(injected)
        sys.modules[name]=module
        # Compile verified Git bytes directly: ignored/stale __pycache__ is
        # neither located nor read, irrespective of timestamp/size matches.
        exec(compile(data,str(path),'exec'),module.__dict__)
        return module

def bootstrap(launcher,plan_path=None):
    trusted=ReviewedLauncher(launcher)
    trusted.tracked(pathlib.Path(__file__))
    for name,expected in CLEANUP_PINS.items():
        boot_require(hashlib.sha256(trusted.tracked(HERE/name)).hexdigest()==expected,'cleanup_pin')
    plan_data=None if plan_path is None else trusted.tracked(plan_path)
    return trusted,plan_data

def load_helpers(trusted):
    global V
    for name in HELPERS:trusted.tracked(HERE/name)
    def load_parser():return trusted.module('pinned_producer_artifacts',HERE/'producer_artifacts.py')
    V=trusted.module('retry03_verifier',HERE/'verify_option.py',_reviewed_parser=load_parser)
    return V

def trusted_cleanup(trusted):
    """Uses only tracked/pinned L snapshot; P/H/plan are irrelevant here."""
    snapshot=pathlib.Path(tempfile.mkdtemp(prefix='wholepact-financial-cleanup-',dir=os.environ['RUNNER_TEMP']))
    try:
        for name,expected in CLEANUP_PINS.items():
            data=trusted.tracked(HERE/name);boot_require(hashlib.sha256(data).hexdigest()==expected,'cleanup_pin')
            destination=snapshot/pathlib.Path(name).relative_to('cleanup_snapshot')
            destination.parent.mkdir(parents=True,exist_ok=True);destination.write_bytes(data);destination.chmod(0o444)
        env={k:os.environ[k] for k in CI_KEYS};env.update(git_env())
        # Snapshot has no __pycache__, ignored extras, P/H imports or symlinks.
        command=[sys.executable,'-I','-B',str(snapshot/'scripts/ci-financial-supervisor.py'),'cleanup']
        child=subprocess.Popen(command,cwd=snapshot,env=env,stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,start_new_session=True)
        try:
            # Original cleanup owns its existing per-command bounds. Do not
            # introduce a shorter aggregate timeout over those operations.
            output,_=child.communicate()
            boot_require(len(output)<=1024*1024,'cleanup_output')
            if output:sys.stdout.buffer.write(output);sys.stdout.buffer.flush()
            return child.returncode==0
        except BaseException:
            if child.poll() is None:
                os.killpg(child.pid,signal.SIGKILL);child.wait(timeout=10)
            raise
    finally:shutil.rmtree(snapshot)


def digest(path):
    with pathlib.Path(path).open('rb') as stream:return hashlib.file_digest(stream,'sha256').hexdigest()


def load_json(path):
    raw=pathlib.Path(path).read_bytes();V.require(len(raw)<=8*1024*1024,'input_size')
    return json.loads(raw,object_pairs_hook=V.A.pairs)


def validate_plan(plan):
    V.require(type(plan) is dict and set(plan)=={'version','producer','harness','artifact_pins',
        'api_pins','reviewed_runtime_changes'},'plan_schema')
    V.require(type(plan['version']) is int and plan['version']==1,'plan_version')
    V.require(plan['producer']==V.PRODUCER,'producer_pin')
    h=plan['harness']
    V.require(type(h) is dict and set(h)=={'repository','source','source_tree'}
        and h['repository']==V.PRODUCER['repository']
        and type(h['source']) is str and V.A.COMMIT.fullmatch(h['source'])
        and type(h['source_tree']) is str and V.A.COMMIT.fullmatch(h['source_tree']),'harness_pin')
    V.require(type(plan['artifact_pins']) is dict and
        set(plan['artifact_pins'])=={'artifact_id','archive_sha256','bundle_sha256'},'artifact_pins')
    p=plan['artifact_pins']
    V.require(type(p['artifact_id']) is int and p['artifact_id']>0,'artifact_id')
    for key in ('archive_sha256','bundle_sha256'):
        V.require(type(p[key]) is str and V.A.SHA.fullmatch(p[key]),'artifact_digest')
    V.require(type(plan['api_pins']) is dict and set(plan['api_pins'])=={'run','artifact','job'},'api_pins')
    for value in plan['api_pins'].values():V.require(type(value) is str and V.A.SHA.fullmatch(value),'api_digest')
    changes=plan['reviewed_runtime_changes'];V.A.closure(changes)
    V.require(set(changes)<=V.RUNTIME_ONLY,'reviewed_change_set')
    return plan


def validate_job(job):
    V.require(type(job) is dict and job.get('id')==V.JOB_ID and type(job.get('id')) is int
        and job.get('run_id')==V.PRODUCER['run_id'] and type(job.get('run_id')) is int
        and job.get('name')=='synthetic-only' and job.get('status')=='completed'
        and job.get('conclusion') in ('failure','success'),'producer_job')
    rows=[s for s in job.get('steps',[]) if s.get('name')=='Preserve exact credential-free compiled financial bundle']
    V.require(len(rows)==1 and rows[0].get('status')=='completed' and rows[0].get('conclusion')=='success','producer_upload')


def safe_environment():
    # No API credential is accepted at this boundary, even though child envs are
    # independently allowlisted. Acquisition is a separate process/CI step.
    forbidden=[k for k in os.environ if any(w in k.upper() for w in ('TOKEN','PASSWORD','SECRET','CREDENTIAL'))]
    V.require(not forbidden,'credential_environment')
    return dict(PATH=os.environ['PATH'],HOME='/nonexistent',GIT_CONFIG_NOSYSTEM='1',
        GIT_CONFIG_GLOBAL='/dev/null',GIT_TERMINAL_PROMPT='0')


def verify_sources(plan,producer_root,harness_root,launcher_root):
    """Never import H modules before verifying its complete source projection."""
    validate_plan(plan);safe_environment()
    V.require(os.environ.get('GITHUB_SHA') not in (plan['producer']['source'],plan['harness']['source']),
        'separate_launcher')
    roots=[pathlib.Path(p).resolve() for p in (producer_root,harness_root,launcher_root)]
    V.require(len(set(roots))==3 and all(not a.is_relative_to(b) for a in roots for b in roots if a!=b),'checkout_separation')
    p_tree,p_inv=V.inventory_checkout(roots[0],V.PRODUCER['source'])
    h_tree,h_inv=V.inventory_checkout(roots[1],plan['harness']['source'])
    l_sha=os.environ.get('GITHUB_SHA','');l_tree,l_inv=V.inventory_checkout(roots[2],l_sha)
    V.require(HERE.is_relative_to(roots[2]),'launcher_location')
    V.require(p_tree==V.PRODUCER['source_tree'] and h_tree==plan['harness']['source_tree'],'tree_identity')
    changes=V.equivalent(p_inv,h_inv)
    V.require({k:h_inv[k] for k in changes}==plan['reviewed_runtime_changes'],'unreviewed_runtime_delta')
    return p_inv,h_inv,dict(repository=V.PRODUCER['repository'],source=l_sha,source_tree=l_tree)


def verified_api(staging,plan):
    values={}
    for name,expected in plan['api_pins'].items():
        p=pathlib.Path(staging)/(name+'.json');V.require(digest(p)==expected,'api_file_changed')
        values[name]=load_json(p)
    validate_job(values['job'])
    return values


def load_supervisor(harness_root):
    path=pathlib.Path(harness_root)/'scripts/ci-financial-supervisor.py'
    module=types.ModuleType('verified_harness_supervisor');module.__file__=str(path)
    sys.modules[module.__name__]=module
    exec(compile(path.read_bytes(),str(path),'exec'),module.__dict__)
    return module


def acquire_verified_inputs(root,staging,plan,p_inv,h_inv):
    """No network, tar extraction API, runtime output or credential persistence."""
    api=verified_api(staging,plan);archive=pathlib.Path(staging)/'producer.zip'
    V.archive_digest(archive,plan['artifact_pins'])
    bundle=root/'original-build.tar'
    with zipfile.ZipFile(archive) as z:
        with z.open('build.tar') as source,bundle.open('xb') as destination:shutil.copyfileobj(source,destination)
    bundle.chmod(0o400)
    evidence=V.qualify(bundle,archive,plan['artifact_pins'],api['run'],api['artifact'],p_inv,h_inv,plan['harness'])
    inputs=root/'artifacts';inputs.mkdir(mode=0o700)
    # The strict verifier has checked every header, name, mode and byte digest.
    # Stream the named entries to newly-created explicit paths; never extractall.
    with tarfile.open(bundle,'r:') as tar:
        for name in V.A.NAMES:
            member=tar.getmember(name);V.require(member.isfile() and member.name==name,'staging_member')
            path=inputs/name
            with tar.extractfile(member) as source,path.open('xb') as destination:shutil.copyfileobj(source,destination)
            path.chmod(0o555)
            V.require(V.A.file_pin(path)==evidence['original_manifest']['files'][name],'staging_digest')
    (root/'original-manifest.json').write_bytes(V.A.canonical(evidence['original_manifest']))
    return inputs,evidence


def stage_image_context(S,root,inputs,h_sha):
    S.package_preflight();S.exact_source(h_sha)
    S.require(S.A.RECIPE==V.A.RECIPE and S.FEATURES==V.A.RECIPE['artifact_features'],'compile','artifact_bundle')
    # Check exact fixture selector before any runtime fixture; this is not a build.
    listing=S.checked([str(inputs/'pristine-setup'),'--list','--exact',S.LIVE_FIXTURE_TEST],
        'compile',seconds=30,limit=4096,env=safe_environment())
    S.require(listing.decode('utf-8').splitlines()==[S.LIVE_FIXTURE_TEST+': test','','1 test, 0 benchmarks'],
        'compile','artifact_profile')
    context=root/'context'
    args=[sys.executable,'-I','-B',str(S.HERE/'ci-financial-image.py'),'--output',str(context),'--source-commit',h_sha]
    for name in S.I.ARTIFACT_FILES:args+=['--'+name,str(inputs/name)]
    S.checked(args,'packages',seconds=900,limit=1024*1024,env={'PATH':os.environ['PATH'],'HOME':'/nonexistent'})
    S.exact_source(h_sha);return context


def runtime_commands(S,context,token,h_sha):
    """Same functions and argument values as fresh main after input acquisition."""
    tag='wholepact-financial:'+token
    S.docker(['pull','--platform','linux/amd64',S.BASE],'image',seconds=300,limit=4*1024*1024)
    foundation_tag='wholepact-financial-foundation:'+token
    foundation=S.build_image(context,'foundation',foundation_tag,token,h_sha,fresh=True)
    image_id=S.final_image(context,tag,foundation_tag,token,h_sha,foundation)
    S.exact_source(h_sha)
    return S.run_case('external',image_id,token,h_sha)


def run_owned(S,root,staging,plan,p_inv,h_inv,launcher,token,*,cleanup_only=False):
    h_sha=plan['harness']['source'];tag='wholepact-financial:'+token
    passed,first=cleanup_only,None
    try:
        if not cleanup_only:
            S.exact_source(h_sha)
            # Whole H test suite is mandatory, including actual AF_UNIX bind.
            for args in ([sys.executable,'-I','-B','scripts/ci-financial-launch-tests.py'],
                         [sys.executable,'-I','-B','-m','unittest','discover','-s','scripts/tests','-p','test_ci_financial*.py']):
                S.checked(args,'preflight',seconds=300,limit=1024*1024,env=safe_environment())
            S.exact_source(h_sha)
            inputs,evidence=acquire_verified_inputs(root,staging,plan,p_inv,h_inv)
            S.emit('REUSE_SOURCE',dict(native_producer=V.PRODUCER,harness=plan['harness'],launcher=launcher,
                artifact_pins=plan['artifact_pins'],original_manifest_sha256=digest(root/'original-manifest.json'),
                native_binaries_reused=True,native_binaries_freshly_compiled=False,
                financial_session_seconds=1800,original_fixture_ceiling_seconds=900,
                public_chain_verified=False,dispatch_requested=False))
            context=stage_image_context(S,root,inputs,h_sha)
            result,passed=runtime_commands(S,context,token,h_sha)
    except S.Failure as error:
        first=S.failure_record(error)
        if not getattr(error,'published',False):S.emit('FAILURE',dict(**first,cleanup_pending=True))
    except Exception:
        first=S.failure_record(S.Failure('supervisor','internal'));S.emit('FAILURE',dict(**first,cleanup_pending=True))
    finally:
        try:clean=S.cleanup(token,tag)
        except Exception:clean=False
        try:shutil.rmtree(root)
        except OSError:clean=False
        passed=passed and clean and first is None
        S.emit('REUSE_RESULT',dict(passed=passed,cleanup_only=cleanup_only,native_producer=V.PRODUCER,
            harness=plan['harness'],launcher=launcher,native_binaries_reused=not cleanup_only,
            native_binaries_freshly_compiled=False,profile=S.P.C.EXTERNAL_PROFILE,
            synthetic_external_witness_flow_verified=passed and not cleanup_only,
            synthetic_full_native_verified=False,integrated_witness_services=7,retained_inert_witnesses=6,
            containers_and_image_removed=clean,public_chain_verified=False,dispatch_requested=False,deployment_verified=False))
    return 0 if passed else 1


def main():
    os.umask(0o077)
    boot_require(len(sys.argv)>=3,'arguments')
    mode=sys.argv[1]
    if mode=='cleanup':
        boot_require(len(sys.argv)==3,'arguments')
        trusted,_=bootstrap(sys.argv[2])
        return 0 if trusted_cleanup(trusted) else 1
    if mode=='acquire':
        boot_require(len(sys.argv)==5,'arguments')
        _,_,plan_path,staging,launcher=sys.argv
        trusted,raw=bootstrap(launcher,plan_path);load_helpers(trusted)
        acquisition=trusted.module('reviewed_acquisition',HERE/'acquire_archive.py',L=sys.modules[__name__])
        return acquisition.acquire_command(raw,staging)
    boot_require(mode=='run' and len(sys.argv)==7,'arguments')
    _,_,plan_path,producer,harness,staging,launcher=sys.argv
    # Trust L and its immutable cleanup before touching a plan, helper or P/H.
    trusted,_=bootstrap(launcher)
    owned_completed=False
    try:
        raw=trusted.tracked(plan_path);load_helpers(trusted)
        plan=validate_plan(json.loads(raw,object_pairs_hook=V.A.pairs))
        p_inv,h_inv,l_identity=verify_sources(plan,producer,harness,launcher)
        os.chdir(harness);S=load_supervisor(harness)
        event,token=S.context();V.require(event==l_identity['source'],'launcher_event')
        S.exact_source(plan['harness']['source'])
        root=pathlib.Path(tempfile.mkdtemp(prefix='wholepact-financial-',dir=os.environ['RUNNER_TEMP']))
        (root/'docker').mkdir();os.environ['FINANCIAL_DOCKER_CONFIG']=str(root/'docker')
        def interrupted(_signal,_frame):raise S.Failure('supervisor','interrupted')
        signal.signal(signal.SIGTERM,interrupted);signal.signal(signal.SIGINT,interrupted)
        status=run_owned(S,root,pathlib.Path(staging).resolve(),plan,p_inv,h_inv,l_identity,token)
        owned_completed=True
    except BaseException:
        print('CI_FINANCIAL_REUSE_PREFLIGHT {"passed":false,"code":"verification_failed"}',flush=True)
        status=1
    # Independent trusted cleanup remains reachable on plan/source/preflight
    # failure and cannot import anything from a dirty or missing P/H checkout.
    if owned_completed:
        # run_owned already gates its final evidence on actual owned cleanup.
        # No second mandatory cleanup may fail after a successful final record.
        return status
    clean=trusted_cleanup(trusted)
    return status if clean else 1

if __name__=='__main__':
    try:sys.exit(main())
    except Exception:
        print('CI_FINANCIAL_REUSE_PREFLIGHT {"passed":false,"code":"verification_failed"}',flush=True)
        sys.exit(1)
