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
PARSER_SHA='53ae1125701112917530d45c04df18e785afa8e973a9d9b7d0de0a77a95dee50'
# Source-bound callback executes verified parser bytes without bytecode.
assert hashlib.sha256((HERE/'producer_artifacts.py').read_bytes()).hexdigest()==PARSER_SHA
A=_reviewed_parser()
QUALIFICATION_PROFILE='coordinated-financial-rendered-host-semantic-v1'
POLICY='p26-observation-diagnostics-reuse-v1'

PRODUCER=dict(repository='stanleykosi/pactloom',source='8f1d67bdef50d886955d026e5fce2c8e8635ecbb',
 source_tree='82591c243dc981cafee4e768db3339ae31994ecc',run_id=39864693253,attempt=1)
JOB_ID=120123827440
# Exact existing runtime files, NOT a suffix/directory exclusion. Contract,
# output projection, fixture profile/scenario, image and orchestration are fixed.
# Original eight paths unchanged. The separate v5 annex admits only two exact reviewed diagnostic byte/mode pairs.
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


DIAGNOSTIC_COMPATIBILITY={'version': 1, 'name': 'observer30-exact-diagnostics-v1', 'files': {'scripts/ci-financial-contract.py': {'producer_git_blob': 'af880f7dbbcfce22c22ccc35b2828c3be5cf893d', 'producer_sha256': 'c273975d5384b6c0d61c15881cce8da77d57fe2a75c9fccac489892a8ea97bc2', 'producer_mode': '100644', 'producer_mode_sha256': '3c355c49a6b7c57f4ed5a59658fa9d6300fe916e3e87f2e9662216fcc50a49c4', 'harness_git_blob': '8cb62540f1405d9ed016ebf92c95edd0bb719244', 'harness_sha256': 'f495a9f6adc783b6c8ad6427e7f5f19d1237fdd9a9a385d34683314f03b700dd', 'harness_mode': '100644', 'harness_mode_sha256': '01b201d560c3f81eb4a20f9b204ac6116553964f1a09b9395d54242123216b41'}, 'scripts/ci-financial-supervisor.py': {'producer_git_blob': 'ab44f75fc60ae6e67ec9e8bf3981492effb5d6ab', 'producer_sha256': '3f7496bb716869622e77b37b061262c8053a7518a8b3a7f48f11be0ff0deb6fd', 'producer_mode': '100644', 'producer_mode_sha256': '1fab5efee2a6913acc944eaf2c821331edbaecbeb12b07a6fb167ec01a0477fb', 'harness_git_blob': '36d051b1666c5f434230b7ad3af0ada59356a5c9', 'harness_sha256': '50118fd69f010a06c93177095f1636aa652a12796ce7fceedb5364fc0f8d02ad', 'harness_mode': '100644', 'harness_mode_sha256': '0e752367fde4adc1adb58c5c40a05887152f753dfb51c8da27a043429f679710'}}}

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


def validate_diagnostic_compatibility(annex):
    require(type(annex) is dict and set(annex)=={'version','name','files'},'diagnostic_annex_schema')
    require(type(annex['version']) is int and annex['version']==1 and type(annex['name']) is str,'diagnostic_annex_type')
    require(type(annex['files']) is dict and set(annex['files'])==set(DIAGNOSTIC_COMPATIBILITY['files']),'diagnostic_annex_paths')
    for path,pair in annex['files'].items():
        require(type(pair) is dict and set(pair)==set(DIAGNOSTIC_COMPATIBILITY['files'][path]),'diagnostic_annex_pair')
        require(all(type(v) is str for v in pair.values()),'diagnostic_annex_type')
    require(annex==DIAGNOSTIC_COMPATIBILITY,'diagnostic_annex_pin')
    return annex


def equivalent(producer,current,diagnostic_compatibility=None):
    A.closure(producer);A.closure(current)
    require(set(producer)==set(current),'tracked_path_set')
    changed=sorted(name for name in producer if producer[name]!=current[name])
    exceptions=set()
    if diagnostic_compatibility is not None:
        annex=validate_diagnostic_compatibility(diagnostic_compatibility)
        for path,pair in annex['files'].items():
            require(path in changed and producer.get(path)==pair['producer_mode_sha256']
                and current.get(path)==pair['harness_mode_sha256'],'diagnostic_annex_source')
            exceptions.add(path)
    require(set(changed)<=RUNTIME_ONLY|exceptions,'native_or_unreviewed_input_changed')
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


def qualify(bundle,archive,pins,run,artifact,producer_inventory,current_inventory,harness,diagnostic_compatibility=None):
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
    name='financial-build-39864693253-1-'+PRODUCER['source']
    origin=artifact.get('workflow_run',{})
    require(artifact.get('id')==pins['artifact_id'] and type(artifact.get('id')) is int
        and artifact.get('name')==name and artifact.get('expired') is False
        and origin.get('id')==PRODUCER['run_id'] and type(origin.get('id')) is int
        and origin.get('head_sha')==PRODUCER['source']
        and artifact.get('digest')=='sha256:'+pins['archive_sha256'],'artifact_origin')
    with pathlib.Path(bundle).open('rb') as stream:bundle_digest=hashlib.file_digest(stream,'sha256').hexdigest()
    require(bundle_digest==pins['bundle_sha256'],'bundle_digest')
    # Original full closure stays exact, including all old runtime files.
    original=A.verify_bundle(bundle,PRODUCER,producer_inventory,QUALIFICATION_PROFILE)
    require(type(harness) is dict and set(harness)=={'repository','source','source_tree'},'harness_identity')
    require(harness['repository']==PRODUCER['repository'] and
        A.COMMIT.fullmatch(harness['source']) is not None and
        A.COMMIT.fullmatch(harness['source_tree']) is not None,'harness_identity')
    changes=equivalent(producer_inventory,current_inventory,diagnostic_compatibility)
    require(not changes or (harness['source']!=PRODUCER['source'] and
        harness['source_tree']!=PRODUCER['source_tree']),'contradictory_harness_identity')
    evidence=dict(schema=5,policy=POLICY,qualification_profile=QUALIFICATION_PROFILE,native_producer=PRODUCER.copy(),harness=harness.copy(),
        original_manifest=original,current_source_inventory=current_inventory.copy(),
        permitted_runtime_changes=[name for name in changes if name in RUNTIME_ONLY],artifact_pins=pins.copy(),
        native_binaries_reused=True,native_binaries_freshly_compiled=False,
        runtime_verified=False,synthetic_full_native_verified=False,
        public_chain_verified=False,dispatch_requested=False)
    if diagnostic_compatibility is not None:evidence['diagnostic_compatibility']=diagnostic_compatibility.copy()
    return evidence
