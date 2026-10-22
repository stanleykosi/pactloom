"""PRIVATE proof-only option. No downloads, extraction, execution or CI activation.

Caller must acquire metadata and reviewed pins from authenticated GitHub API and
original producer logs, not from an artifact's own claims. No current-run reuse
claim is possible until actual artifact ID/archive/bundle hashes are pinned.
"""
import hashlib
import importlib.util
import pathlib
import subprocess
import os
import stat
import zipfile

HERE=pathlib.Path(__file__).resolve().parent
PARSER_SHA='d24433f973c77d34e6d1f5c299cc1c7d00a7d024584bbfcb3d45e077c0e92f5d'
# Source-bound callback executes verified parser bytes without bytecode.
assert hashlib.sha256((HERE/'producer_artifacts.py').read_bytes()).hexdigest()==PARSER_SHA
A=_reviewed_parser()

PRODUCER=dict(repository='stanleykosi/pactloom',source='6f00b00454ba062bea40d1f1e73efe0165ae8aa2',
 source_tree='d367a59509acef544d75de4120cbe5f991375e7b',run_id=39792448140,attempt=1)
JOB_ID=119871612406
# Exact existing runtime files, NOT a suffix/directory exclusion. Contract,
# output projection, fixture profile/scenario, image and orchestration are fixed.
RUNTIME_ONLY=frozenset((
 'scripts/ci-financial-container.py',
 'scripts/ci-financial-fixture.py',
 'scripts/ci-financial-flow.py',
 'scripts/ci-financial-observer.py',
 'scripts/ci-financial-controller.py',
 'scripts/ci-financial-external-operator.py',
 'scripts/tests/test_ci_financial_observer.py',
 'scripts/tests/test_ci_financial_fixture_diagnostics.py',
))


def require(ok,reason):
    if not ok:raise A.Rejected(reason)


def inventory_checkout(root,commit):
    """Must be independently run on both exact clean Git checkouts."""
    root=pathlib.Path(root).resolve()
    def git(*args):return subprocess.check_output(['git','-C',str(root),*args],
        env={'PATH':os.environ['PATH'],'HOME':'/nonexistent','GIT_CONFIG_NOSYSTEM':'1',
             'GIT_CONFIG_GLOBAL':'/dev/null','GIT_TERMINAL_PROMPT':'0'})
    require(A.COMMIT.fullmatch(commit) is not None,'commit')
    require(git('rev-parse','HEAD').strip().decode()==commit,'checkout_commit')
    require(git('status','--porcelain','--untracked-files=all')==b'','dirty_checkout')
    # A -B interpreter can still READ stale bytecode. Refuse ignored extras in
    # all execution sources, so H's unchanged import helpers cannot read one.
    require(git('ls-files','--others','--ignored','--exclude-standard','-z')==b'','ignored_checkout_input')
    tree=git('rev-parse','HEAD^{tree}').strip().decode()
    result={}
    for row in git('ls-tree','-rz','--full-tree','HEAD').split(b'\0'):
        if not row:continue
        fields,path=row.split(b'\t',1);mode,kind,oid=fields.split(b' ')
        require(mode in (b'100644',b'100755') and kind==b'blob','source_kind')
        name=path.decode('ascii');A.closure({name:'0'*64})
        # Read the tracked Git blob, bind its declared mode, compare working bytes.
        data=git('cat-file','blob',oid.decode())
        local=root/name
        require(not local.is_symlink() and local.is_file() and local.read_bytes()==data
            and stat.S_IMODE(local.stat().st_mode)==(int(mode,8)&0o777),'source_bytes')
        result[name]=hashlib.sha256(mode+b'\0'+data).hexdigest()
    A.closure(result)
    return tree,result


def equivalent(producer,current):
    A.closure(producer);A.closure(current)
    require(set(producer)==set(current),'tracked_path_set')
    changed=sorted(name for name in producer if producer[name]!=current[name])
    require(set(changed)<=RUNTIME_ONLY,'native_or_unreviewed_input_changed')
    # Empty change is valid; it does not imply runtime acceptance.
    return changed


def archive_digest(archive,pins):
    archive=pathlib.Path(archive)
    require(archive.is_file() and not archive.is_symlink(),'archive_file')
    require(0<archive.stat().st_size<=A.MAX_TOTAL+A.MAX_MANIFEST+1024*1024,'archive_size')
    with archive.open('rb') as stream:digest=hashlib.file_digest(stream,'sha256').hexdigest()
    require(digest==pins['archive_sha256'],'archive_digest')
    with zipfile.ZipFile(archive) as zipped:
        entries=zipped.infolist()
        require(len(entries)==1 and entries[0].filename=='build.tar' and not entries[0].is_dir()
            and entries[0].file_size<=A.MAX_TOTAL+A.MAX_MANIFEST+65536,'zip_entries')
        with zipped.open(entries[0]) as stream:tar_digest=hashlib.file_digest(stream,'sha256').hexdigest()
        require(tar_digest==pins['bundle_sha256'],'zip_bundle_digest')
    return digest


def qualify(bundle,archive,pins,run,artifact,producer_inventory,current_inventory,harness):
    """Pins are independently reviewed API/log facts; never manifest-supplied.

    ZIP must contain exactly build.tar with independently pinned bytes.
    Both archive and TAR are checked; no extraction or execution occurs.
    """
    require(type(pins) is dict and set(pins)=={'artifact_id','archive_sha256','bundle_sha256'},'pin_set')
    require(type(pins['artifact_id']) is int and pins['artifact_id']>0,'artifact_pin')
    for key in ('archive_sha256','bundle_sha256'):
        require(type(pins[key]) is str and A.SHA.fullmatch(pins[key]) is not None,'digest_pin')
    archive_digest(archive,pins)
    require(run.get('id')==PRODUCER['run_id'] and type(run.get('id')) is int
        and run.get('run_attempt')==1 and type(run.get('run_attempt')) is int
        and run.get('head_sha')==PRODUCER['source']
        and run.get('head_branch')=='qualification/durable-proposal-v1'
        and run.get('event')=='push' and run.get('status')=='completed'
        and run.get('path')=='.github/workflows/durable-native-linux.yml'
        and run.get('repository',{}).get('full_name')==PRODUCER['repository'],'producer_run')
    # A runtime-failed job is expected and does not invalidate its pre-fixture build.
    require(run.get('conclusion') in ('failure','success'),'producer_terminal')
    name='financial-build-39792448140-1-'+PRODUCER['source']
    origin=artifact.get('workflow_run',{})
    require(artifact.get('id')==pins['artifact_id'] and type(artifact.get('id')) is int
        and artifact.get('name')==name and artifact.get('expired') is False
        and origin.get('id')==PRODUCER['run_id'] and type(origin.get('id')) is int
        and origin.get('head_sha')==PRODUCER['source']
        and artifact.get('digest')=='sha256:'+pins['archive_sha256'],'artifact_origin')
    with pathlib.Path(bundle).open('rb') as stream:bundle_digest=hashlib.file_digest(stream,'sha256').hexdigest()
    require(bundle_digest==pins['bundle_sha256'],'bundle_digest')
    # Original full closure stays exact, including all old runtime files.
    original=A.verify_bundle(bundle,PRODUCER,producer_inventory)
    require(type(harness) is dict and set(harness)=={'repository','source','source_tree'},'harness_identity')
    require(harness['repository']==PRODUCER['repository'] and
        A.COMMIT.fullmatch(harness['source']) is not None and
        A.COMMIT.fullmatch(harness['source_tree']) is not None,'harness_identity')
    changes=equivalent(producer_inventory,current_inventory)
    require(not changes or (harness['source']!=PRODUCER['source'] and
        harness['source_tree']!=PRODUCER['source_tree']),'contradictory_harness_identity')
    return dict(schema=1,native_producer=PRODUCER.copy(),harness=harness.copy(),
        original_manifest=original,current_source_inventory=current_inventory.copy(),
        permitted_runtime_changes=changes,artifact_pins=pins.copy(),
        native_binaries_reused=True,native_binaries_freshly_compiled=False,
        runtime_verified=False,synthetic_full_native_verified=False,
        public_chain_verified=False,dispatch_requested=False)
